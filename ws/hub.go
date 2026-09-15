package ws

import (
	"encoding/json"
	"log"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

const (
	flowSendBufferSize      = 256
	controlSendBufferSize   = 64
	flowBroadcastBufferSize = 1024
	controlBroadcastSize    = 64
	flowDropLogInterval     = time.Minute
)

// Client represents a single connected browser client. Flow traffic uses a
// separate lossy queue so a temporarily slow browser cannot disconnect itself
// merely because live packet updates arrive quickly.
type Client struct {
	conn       *websocket.Conn
	remoteAddr string
	control    chan []byte
	flow       chan []byte

	droppedFlows    uint64
	lastFlowDropLog time.Time
	disconnectOnce  sync.Once
}

func newClient(conn *websocket.Conn, remoteAddr string) *Client {
	return &Client{
		conn:       conn,
		remoteAddr: remoteAddr,
		control:    make(chan []byte, controlSendBufferSize),
		flow:       make(chan []byte, flowSendBufferSize),
	}
}

// Hub manages all connected WebSocket clients.
type Hub struct {
	clients    map[*Client]struct{}
	register   chan *Client
	unregister chan *Client
	control    chan []byte
	flow       chan []byte

	mu                   sync.Mutex
	droppedFlowBroadcast uint64
	lastFlowDropLog      time.Time
}

// NewHub creates an initialised Hub ready to Run.
func NewHub() *Hub {
	return &Hub{
		clients:    make(map[*Client]struct{}),
		register:   make(chan *Client),
		unregister: make(chan *Client),
		control:    make(chan []byte, controlBroadcastSize),
		flow:       make(chan []byte, flowBroadcastBufferSize),
	}
}

// Run processes hub events. Must be called in its own goroutine.
func (h *Hub) Run() {
	for {
		// Prefer alerts, status, and other control messages over the high-rate
		// packet stream whenever both are waiting.
		select {
		case msg := <-h.control:
			h.deliverControl(msg)
			continue
		default:
		}

		select {
		case client := <-h.register:
			h.clients[client] = struct{}{}
			log.Printf("ws/hub: client connected remote=%s", client.remoteAddr)

		case client := <-h.unregister:
			h.removeClient(client)

		case msg := <-h.control:
			h.deliverControl(msg)

		case msg := <-h.flow:
			h.deliverFlow(msg)
		}
	}
}

func (h *Hub) removeClient(client *Client) {
	if _, ok := h.clients[client]; !ok {
		return
	}
	delete(h.clients, client)
	close(client.control)
	close(client.flow)
	log.Printf("ws/hub: client removed remote=%s", client.remoteAddr)
}

func (h *Hub) deliverControl(msg []byte) {
	for client := range h.clients {
		// Control events are deliberately not dropped. They are infrequent, and
		// preserving alerts/status is more important than packet-stream latency.
		client.control <- msg
	}
}

func (h *Hub) deliverFlow(msg []byte) {
	for client := range h.clients {
		select {
		case client.flow <- msg:
		default:
			h.noteClientFlowDrop(client)
		}
	}
}

func (h *Hub) noteClientFlowDrop(client *Client) {
	client.droppedFlows++
	now := time.Now()
	if !client.lastFlowDropLog.IsZero() && now.Sub(client.lastFlowDropLog) < flowDropLogInterval {
		return
	}
	log.Printf("ws/hub: flow queue full remote=%s; dropped_flow_updates=%d (client remains connected)", client.remoteAddr, client.droppedFlows)
	client.droppedFlows = 0
	client.lastFlowDropLog = now
}

// Broadcast marshals msg and enqueues it for connected clients. Live flow/DNS
// updates are lossy under pressure; alerts and status/control messages wait
// for delivery instead of being silently discarded behind packet traffic.
func (h *Hub) Broadcast(msg interface{}) {
	data, err := json.Marshal(msg)
	if err != nil {
		log.Printf("ws/hub: marshal error: %v", err)
		return
	}
	if isLossyLiveMessage(msg) {
		select {
		case h.flow <- data:
		default:
			h.noteBroadcastFlowDrop()
		}
		return
	}
	h.control <- data
}

func isLossyLiveMessage(msg interface{}) bool {
	switch msg.(type) {
	case *FlowMessage, FlowMessage, *DNSMessage, DNSMessage, *EnrichmentMessage, EnrichmentMessage:
		return true
	default:
		return false
	}
}

func (h *Hub) noteBroadcastFlowDrop() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.droppedFlowBroadcast++
	now := time.Now()
	if !h.lastFlowDropLog.IsZero() && now.Sub(h.lastFlowDropLog) < flowDropLogInterval {
		return
	}
	log.Printf("ws/hub: flow broadcast queue full; dropped_flow_updates=%d", h.droppedFlowBroadcast)
	h.droppedFlowBroadcast = 0
	h.lastFlowDropLog = now
}
