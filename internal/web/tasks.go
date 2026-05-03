// Package web — task tracking and cancellation surface.
//
// Long-running operations (triage, hunt, memory analysis) register
// themselves here at start so the SPA's floating cancel bar can show the
// active task and let the analyst stop it. The pattern from the caller's
// side is:
//
//	taskID, taskCtx, cancel := StartTask("Quick Triage: full")
//	defer cancel()
//	go func() {
//	    defer CompleteTask(taskID, "completed")
//	    // pass taskCtx into anything that should abort on cancel
//	}()
//
// Cancellation cascades two ways: the context is cancelled (so any
// exec.CommandContext-spawned subprocess gets killed and ctx.Done()
// loops exit) AND, if the caller registered a Cmd via SetTaskCmd, that
// process is killed directly.
package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"sync"
	"time"
)

// RunningTask is one in-flight unit of work registered with the manager.
// JSON-tagged fields are surfaced via /api/tasks; Cancel and Cmd are
// internal handles never serialised.
type RunningTask struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	StartedAt time.Time `json:"started_at"`
	Status    string    `json:"status"` // running, completed, cancelled, failed

	cancel context.CancelFunc
	cmd    *exec.Cmd
	mu     sync.Mutex
}

var (
	tasks   = make(map[string]*RunningTask)
	tasksMu sync.RWMutex
)

// StartTask registers a new cancellable task with the global manager.
// Returns the task ID, a context to thread into work that should abort
// on cancel, and the cancel func (caller's defer cancel() releases the
// resources but does not move the task to "cancelled"; CompleteTask
// owns the status transition).
func StartTask(name string) (string, context.Context, context.CancelFunc) {
	id := fmt.Sprintf("task-%d", time.Now().UnixNano())
	ctx, cancel := context.WithCancel(context.Background())

	task := &RunningTask{
		ID:        id,
		Name:      name,
		StartedAt: time.Now().UTC(),
		Status:    "running",
		cancel:    cancel,
	}
	tasksMu.Lock()
	tasks[id] = task
	tasksMu.Unlock()

	broadcastProgress("task_started", map[string]interface{}{
		"task_id":    id,
		"name":       name,
		"started_at": task.StartedAt.Format(time.RFC3339),
	})
	return id, ctx, cancel
}

// SetTaskCmd associates a started exec.Cmd with a task so a subsequent
// CancelTask can kill the process directly. Optional — most callers run
// commands via exec.CommandContext and rely on the ctx for kill
// propagation; this is for cases where the parent goroutine forks a
// long-running child without context support.
func SetTaskCmd(taskID string, cmd *exec.Cmd) {
	tasksMu.RLock()
	task, ok := tasks[taskID]
	tasksMu.RUnlock()
	if !ok {
		return
	}
	task.mu.Lock()
	task.cmd = cmd
	task.mu.Unlock()
}

// CompleteTask marks a task with a terminal status (completed / failed /
// cancelled), broadcasts a task_ended event, and removes the entry from
// the registry. Idempotent — calling twice for the same ID is safe.
func CompleteTask(taskID, status string) {
	tasksMu.Lock()
	task, ok := tasks[taskID]
	if ok {
		delete(tasks, taskID)
	}
	tasksMu.Unlock()
	if !ok {
		return
	}
	task.mu.Lock()
	task.Status = status
	task.mu.Unlock()

	broadcastProgress("task_ended", map[string]interface{}{
		"task_id": taskID,
		"name":    task.Name,
		"status":  status,
	})
}

// CancelTask aborts the named task. Cancels its context (which kills any
// CommandContext children and wakes ctx.Done() consumers) and, when a
// Cmd was registered via SetTaskCmd, terminates that process directly.
// Returns nil on success, or an error when the task isn't running.
//
// CancelTask does NOT call CompleteTask — the goroutine running the work
// is expected to detect the cancellation via ctx.Done() and call
// CompleteTask itself with a "cancelled" status. We do broadcast a
// task_cancelled event so the SPA can hide the cancel bar immediately
// without waiting for the goroutine to wind down.
func CancelTask(taskID string) error {
	tasksMu.RLock()
	task, ok := tasks[taskID]
	tasksMu.RUnlock()
	if !ok {
		return fmt.Errorf("task %s not found", taskID)
	}

	task.mu.Lock()
	defer task.mu.Unlock()
	if task.Status != "running" {
		return fmt.Errorf("task %s is not running (status: %s)", taskID, task.Status)
	}
	if task.cancel != nil {
		task.cancel()
	}
	if task.cmd != nil && task.cmd.Process != nil {
		_ = task.cmd.Process.Kill()
	}
	task.Status = "cancelling"

	broadcastProgress("task_cancelled", map[string]interface{}{
		"task_id": taskID,
		"name":    task.Name,
	})
	return nil
}

// GetRunningTasks returns a snapshot of every task currently in the
// running state. Safe to call from HTTP handlers.
func GetRunningTasks() []RunningTask {
	tasksMu.RLock()
	defer tasksMu.RUnlock()
	out := make([]RunningTask, 0, len(tasks))
	for _, t := range tasks {
		t.mu.Lock()
		if t.Status == "running" || t.Status == "cancelling" {
			out = append(out, RunningTask{
				ID:        t.ID,
				Name:      t.Name,
				StartedAt: t.StartedAt,
				Status:    t.Status,
			})
		}
		t.mu.Unlock()
	}
	return out
}

// RunCancellableCommand wraps exec.CommandContext + SetTaskCmd in one
// call. Use it in place of cmd.CombinedOutput() inside a goroutine
// that's already registered a task — gives the cancel button two ways
// to stop the child (ctx kill + direct Process.Kill).
func RunCancellableCommand(taskID string, ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	SetTaskCmd(taskID, cmd)
	return cmd.CombinedOutput()
}

// ---------------------------------------------------------------------------
// HTTP handlers
// ---------------------------------------------------------------------------

// handleTasksList — GET /api/tasks. Returns every task currently in the
// running state. Used by the SPA when reconnecting after a page reload
// to recover the cancel bar's state.
func handleTasksList(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, GetRunningTasks())
}

// handleTaskCancel — POST /api/tasks/cancel. Body: {"task_id": "<id>"}.
func handleTaskCancel(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	var req struct {
		TaskID string `json:"task_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if req.TaskID == "" {
		writeError(w, http.StatusBadRequest, "task_id is required")
		return
	}
	if err := CancelTask(req.TaskID); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "cancelling",
		"task_id": req.TaskID,
	})
}
