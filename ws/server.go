package ws

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
)

const (
	writeDeadline  = 10 * time.Second
	pongWait       = 70 * time.Second
	pingPeriod     = 50 * time.Second
	maxMessageSize = 64 << 10
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

// Server wraps the HTTP server and WebSocket hub.
type Server struct {
	port int
	hub  *Hub
}

// NewServer creates a Server bound to the given port.
func NewServer(port int, hub *Hub) *Server {
	return &Server{port: port, hub: hub}
}

// Start launches the HTTP server. Blocks until the server exits.
func (s *Server) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", s.handleWS)
	mux.HandleFunc("/", s.handleHealth)

	addr := fmt.Sprintf(":%d", s.port)
	log.Printf("ws/server: listening on %s", addr)
	return http.ListenAndServe(addr, mux)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    "ok",
		"mode":      "local",
		"capturing": true,
	})
}

func (s *Server) handleWS(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("ws/server: upgrade error: %v", err)
		return
	}

	client := newClient(conn, conn.RemoteAddr().String())
	s.hub.register <- client

	go s.writePump(client)
	go s.readPump(client)
}

// writePump is the sole writer for a client connection. It gives control
// messages priority over packet-flow updates and sends conservative pings so
// dead TCP paths are detected even while application traffic is idle.
func (s *Server) writePump(c *Client) {
	pingTicker := time.NewTicker(pingPeriod)
	defer func() {
		pingTicker.Stop()
		s.unregister(c, "write pump stopped")
		_ = c.conn.Close()
	}()

	control, flow := c.control, c.flow
	for control != nil || flow != nil {
		// Drain queued alerts/status before any live packet update.
		select {
		case msg, ok := <-control:
			if !ok {
				control = nil
				continue
			}
			if !s.writeMessage(c, websocket.TextMessage, msg) {
				return
			}
			continue
		default:
		}

		select {
		case msg, ok := <-control:
			if !ok {
				control = nil
				continue
			}
			if !s.writeMessage(c, websocket.TextMessage, msg) {
				return
			}

		case msg, ok := <-flow:
			if !ok {
				flow = nil
				continue
			}
			if !s.writeMessage(c, websocket.TextMessage, msg) {
				return
			}

		case <-pingTicker.C:
			if !s.writeMessage(c, websocket.PingMessage, nil) {
				return
			}
		}
	}
}

func (s *Server) writeMessage(c *Client, messageType int, data []byte) bool {
	if err := c.conn.SetWriteDeadline(time.Now().Add(writeDeadline)); err != nil {
		log.Printf("ws/server: set write deadline remote=%s error=%v", c.remoteAddr, err)
		return false
	}
	if err := c.conn.WriteMessage(messageType, data); err != nil {
		log.Printf("ws/server: write error remote=%s type=%d error=%v", c.remoteAddr, messageType, err)
		return false
	}
	return true
}

// readPump drains incoming frames, handles browser pong replies, and records
// close information. The browser WebSocket API responds to ping frames
// automatically; no application-level heartbeat message is needed.
func (s *Server) readPump(c *Client) {
	defer func() {
		s.unregister(c, "read pump stopped")
		_ = c.conn.Close()
	}()

	c.conn.SetReadLimit(maxMessageSize)
	_ = c.conn.SetReadDeadline(time.Now().Add(pongWait))
	c.conn.SetPongHandler(func(string) error {
		return c.conn.SetReadDeadline(time.Now().Add(pongWait))
	})

	for {
		if _, _, err := c.conn.ReadMessage(); err != nil {
			var closeErr *websocket.CloseError
			if errors.As(err, &closeErr) {
				log.Printf("ws/server: client close remote=%s code=%d reason=%q", c.remoteAddr, closeErr.Code, closeErr.Text)
			} else {
				log.Printf("ws/server: read error remote=%s error=%v", c.remoteAddr, err)
			}
			return
		}
	}
}

func (s *Server) unregister(c *Client, reason string) {
	c.disconnectOnce.Do(func() {
		log.Printf("ws/server: client disconnecting remote=%s reason=%s", c.remoteAddr, reason)
		s.hub.unregister <- c
	})
}
