package ws

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/websocket"
)

// RelayClient connects to the Ahlyx Labs relay server and forwards broadcast messages.
type RelayClient struct {
	sessionID string
	conn      *websocket.Conn
}

type sessionResponse struct {
	SessionID string `json:"session_id"`
	RelayURL  string `json:"relay_url"`
}

// NewRelayClient fetches a session from apiBase and dials the relay WebSocket.
func NewRelayClient(apiBase string) (*RelayClient, error) {
	httpClient := &http.Client{Timeout: 10 * time.Second}
	resp, err := httpClient.Get(apiBase + "/api/v1/pcap/session")
	if err != nil {
		return nil, fmt.Errorf("fetch session: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch session: server returned %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read session response: %w", err)
	}
	var sr sessionResponse
	if err := json.Unmarshal(body, &sr); err != nil {
		return nil, fmt.Errorf("parse session response: %w", err)
	}

	dialer := websocket.Dialer{HandshakeTimeout: 10 * time.Second}
	conn, _, err := dialer.Dial(sr.RelayURL+"?role=agent", nil)
	if err != nil {
		return nil, fmt.Errorf("dial relay %s: %w", sr.RelayURL, err)
	}
	return &RelayClient{sessionID: sr.SessionID, conn: conn}, nil
}

// SessionID returns the relay session ID assigned by the server.
func (rc *RelayClient) SessionID() string {
	return rc.sessionID
}

// Broadcast marshals msg to JSON and writes it to the relay connection.
// If the write fails it logs "relay: connection lost — exiting" and calls os.Exit(1).
func (rc *RelayClient) Broadcast(msg interface{}) {
	data, err := json.Marshal(msg)
	if err != nil {
		log.Printf("relay: marshal error: %v", err)
		return
	}
	if err := rc.conn.WriteMessage(websocket.TextMessage, data); err != nil {
		log.Println("relay: connection lost — exiting")
		os.Exit(1)
	}
}

// Close sends a clean WebSocket close frame and closes the connection.
func (rc *RelayClient) Close() {
	_ = rc.conn.WriteMessage(websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
	rc.conn.Close()
}
