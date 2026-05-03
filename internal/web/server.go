// Package web hosts VanGuard's browser-based frontend. It serves an embedded
// single-page app over HTTP and exposes a JSON API + WebSocket fan-out to
// the same managers the TUI uses (case DB, tool registry, Velociraptor
// lifecycle, etc.) via a shared *app.Context.
//
// The server binds to 127.0.0.1 only — VanGuard runs on the analyst's box,
// not as a network service. Don't change that without adding auth.
package web

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"sync"
	"time"

	"github.com/ridgelinecyberdefence/vanguard/internal/app"
)

// staticFiles is the embedded SPA. Living next to the source means air-gapped
// builds carry the entire UI inside vanguard.exe — no CDN, no extra files
// to ship.
//
//go:embed static/*
var staticFiles embed.FS

// appCtx is the process-wide pointer to the shared application context.
// HTTP handlers read it directly; the alternative — passing it through every
// handler signature — buys little and pollutes the stdlib mux interface. The
// pointer is set once in Run() before the first request can arrive.
var (
	appCtx   *app.Context
	appCtxMu sync.RWMutex
)

func setAppCtx(ctx *app.Context) {
	appCtxMu.Lock()
	defer appCtxMu.Unlock()
	appCtx = ctx
}

func getAppCtx() *app.Context {
	appCtxMu.RLock()
	defer appCtxMu.RUnlock()
	return appCtx
}

// Run boots the web frontend. Blocks until the HTTP server returns (Ctrl+C
// or unrecoverable error). The configured port is tried first; if it's busy
// we walk up to portRange ports before giving up.
func Run(ctx *app.Context, port int) error {
	if ctx == nil {
		return errors.New("web.Run: nil app context")
	}
	setAppCtx(ctx)

	mux := http.NewServeMux()
	registerRoutes(mux)
	mountStatic(mux)

	listener, addr, err := listen(port)
	if err != nil {
		return err
	}
	url := "http://" + addr

	announceStartup(ctx, url)

	// Open the analyst's browser ~half a second after the server is ready.
	// Detached goroutine — if the browser launch fails we still serve.
	go func() {
		time.Sleep(500 * time.Millisecond)
		_ = openBrowser(url)
	}()

	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	if ctx.Logger != nil {
		ctx.Logger.Info("web", "serving on %s", addr)
	}

	// Start serving. http.ErrServerClosed is the clean-shutdown signal.
	if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("http serve: %w", err)
	}
	return nil
}

// listen binds 127.0.0.1:port. If the requested port is already in use, walk
// forward until we find a free one (capped). Returns the listener and the
// resolved bind address.
func listen(port int) (net.Listener, string, error) {
	const portRange = 100
	for p := port; p < port+portRange; p++ {
		addr := fmt.Sprintf("127.0.0.1:%d", p)
		l, err := net.Listen("tcp", addr)
		if err == nil {
			return l, addr, nil
		}
	}
	return nil, "", fmt.Errorf("no free port in range %d-%d", port, port+portRange-1)
}

// announceStartup prints the boot banner. We do this with fmt rather than
// the structured logger because the analyst is staring at the terminal
// waiting for the URL, and a tagged log line buries the URL in metadata.
func announceStartup(ctx *app.Context, url string) {
	fmt.Printf("\n")
	fmt.Printf("  VANGUARD — DFIR Toolkit v%s\n", ctx.Version)
	fmt.Printf("  RidgeLine Cyber\n")
	fmt.Printf("\n")
	fmt.Printf("  Web UI:    %s\n", url)
	fmt.Printf("  Platform:  %s\n", ctx.Platform)
	fmt.Printf("  Elevated:  %v\n", ctx.Elevated)
	fmt.Printf("  Host:      %s\n", ctx.Hostname)
	fmt.Printf("\n")
	fmt.Printf("  Press Ctrl+C to stop. Use --tui to launch the terminal UI instead.\n")
	fmt.Printf("\n")
}

// mountStatic serves the embedded SPA from the root path. Only triggered when
// no API/WS route matches — the API mux entries take priority because their
// patterns are more specific.
func mountStatic(mux *http.ServeMux) {
	staticFS, err := fs.Sub(staticFiles, "static")
	if err != nil {
		// Build-time error: the embed path didn't materialise. Surface it
		// as a 500 on every static request rather than panicking the server.
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "static asset embed missing: "+err.Error(),
				http.StatusInternalServerError)
		})
		return
	}
	mux.Handle("/", http.FileServer(http.FS(staticFS)))
}

// openBrowser fires the OS-default URL handler. Errors are non-fatal — the
// analyst can always paste the URL manually.
func openBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		// `cmd /c start "" <url>` — the empty quoted string is the window
		// title argument start expects, otherwise URLs containing & break.
		cmd = exec.Command("cmd", "/c", "start", "", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	return cmd.Start()
}

// shutdownContext returns a 10-second deadline context for graceful shutdown.
// Exposed for future use (signal-handler integration); unused in the basic
// Ctrl+C path which terminates the process directly.
func shutdownContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 10*time.Second)
}
