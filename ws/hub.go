package ws

import (
	"encoding/json"
	"log"

	"github.com/gorilla/websocket"
)

const sendBufferSize = 256

// Client represents a single connected browser client.
type Client struct {
	conn *websocket.Conn
	send chan []byte
}

// Hub manages all connected WebSocket clients.
type Hub struct {
	clients    map[*Client]struct{}
	register   chan *Client
	unregister chan *Client
	broadcast  chan []byte
}

// NewHub creates an initialised Hub ready to Run.
func NewHub() *Hub {
	return &Hub{
		clients:    make(map[*Client]struct{}),
		register:   make(chan *Client),
		unregister: make(chan *Client),
		broadcast:  make(chan []byte, sendBufferSize),
	}
}

// Run processes hub events. Must be called in its own goroutine.
func (h *Hub) Run() {
	for {
		select {
		case client := <-h.register:
			h.clients[client] = struct{}{}

		case client := <-h.unregister:
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				close(client.send)
			}

		case msg := <-h.broadcast:
			for client := range h.clients {
				select {
				case client.send <- msg:
				default:
					// Slow client: drop message and disconnect.
					delete(h.clients, client)
					close(client.send)
				}
			}
		}
	}
}

// Broadcast marshals msg to JSON and enqueues it for all connected clients.
func (h *Hub) Broadcast(msg interface{}) {
	data, err := json.Marshal(msg)
	if err != nil {
		log.Printf("ws/hub: marshal error: %v", err)
		return
	}
	select {
	case h.broadcast <- data:
	default:
		log.Println("ws/hub: broadcast channel full, dropping message")
	}
}
