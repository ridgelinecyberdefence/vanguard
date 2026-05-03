package web

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// upgrader configures the HTTP→WS handshake. Origin check restricts the
// websocket to local-only connections — VanGuard binds the HTTP server to
// 127.0.0.1, but the upgrader sees the Host header from the request which
// could in theory be spoofed by a same-origin XHR from a malicious local
// page. Keeping the check tight defends against that without giving up the
// no-auth single-user model VanGuard uses on the analyst's box.
var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		host := r.Host
		// Strip port for comparison.
		if i := strings.IndexByte(host, ':'); i >= 0 {
			host = host[:i]
		}
		switch host {
		case "127.0.0.1", "localhost", "[::1]":
			return true
		}
		return false
	},
	ReadBufferSize:  1024,
	WriteBufferSize: 4096,
}

// connSet is the registered set of live websocket clients. All access via
// clientsMu — broadcast and connect/disconnect run on different goroutines.
var (
	clients   = make(map[*websocket.Conn]bool)
	clientsMu sync.Mutex
)

// handleWebSocket — GET /ws. Upgrades the connection and parks it in the
// clients set until the peer disconnects. Incoming messages are drained but
// ignored (the server is broadcast-only for now).
func handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		// Upgrade already wrote a 4xx; nothing else to do.
		return
	}

	clientsMu.Lock()
	clients[conn] = true
	clientsMu.Unlock()

	if ctx := getAppCtx(); ctx != nil && ctx.Logger != nil {
		ctx.Logger.Info("web", "websocket client connected (%d total)", len(clients))
	}

	defer func() {
		clientsMu.Lock()
		delete(clients, conn)
		count := len(clients)
		clientsMu.Unlock()
		_ = conn.Close()
		if ctx := getAppCtx(); ctx != nil && ctx.Logger != nil {
			ctx.Logger.Info("web", "websocket client disconnected (%d total)", count)
		}
	}()

	// Keepalive: respond to pings, drop on idle.
	conn.SetReadDeadline(time.Now().Add(120 * time.Second))
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(120 * time.Second))
		return nil
	})

	for {
		// We don't accept inbound messages, but ReadMessage blocks until
		// the peer sends one or disconnects — that's how we detect close.
		if _, _, err := conn.ReadMessage(); err != nil {
			return
		}
	}
}

// broadcastProgress fans a structured progress message out to every connected
// websocket client. Failed writes evict the client. Safe to call from any
// goroutine.
//
// The wire format the SPA expects:
//
//	{
//	  "type":      "<eventType>",
//	  "data":      <opaque JSON>,
//	  "timestamp": "<RFC3339>"
//	}
func broadcastProgress(eventType string, data interface{}) {
	msg := map[string]interface{}{
		"type":      eventType,
		"data":      data,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}
	payload, err := json.Marshal(msg)
	if err != nil {
		if ctx := getAppCtx(); ctx != nil && ctx.Logger != nil {
			ctx.Logger.Warn("web", "marshal progress %s: %v", eventType, err)
		}
		return
	}

	clientsMu.Lock()
	defer clientsMu.Unlock()
	for conn := range clients {
		// Per-write deadline — a stalled client can't block the broadcast.
		_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if err := conn.WriteMessage(websocket.TextMessage, payload); err != nil {
			_ = conn.Close()
			delete(clients, conn)
		}
	}
}
