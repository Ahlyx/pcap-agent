package ws

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
)

const writeDeadline = 10 * time.Second

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
		"status":     "ok",
		"mode":       "local",
		"capturing":  true,
	})
}

func (s *Server) handleWS(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("ws/server: upgrade error: %v", err)
		return
	}

	client := &Client{
		conn: conn,
		send: make(chan []byte, sendBufferSize),
	}
	s.hub.register <- client

	go s.writePump(client)
	go s.readPump(client)
}

// writePump forwards messages from the send channel to the WebSocket.
func (s *Server) writePump(c *Client) {
	defer c.conn.Close()
	for msg := range c.send {
		if err := c.conn.SetWriteDeadline(time.Now().Add(writeDeadline)); err != nil {
			return
		}
		if err := c.conn.WriteMessage(websocket.TextMessage, msg); err != nil {
			return
		}
	}
}

// readPump drains incoming frames and unregisters the client on disconnect.
func (s *Server) readPump(c *Client) {
	defer func() {
		s.hub.unregister <- c
		c.conn.Close()
	}()
	for {
		if _, _, err := c.conn.ReadMessage(); err != nil {
			return
		}
	}
}
