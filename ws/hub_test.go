package ws

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestSlowFlowConsumerStaysConnectedAndReceivesAlerts(t *testing.T) {
	hub := NewHub()
	client := newClient(nil, "slow-test-client")
	hub.clients[client] = struct{}{}

	for i := 0; i < flowSendBufferSize+32; i++ {
		hub.deliverFlow([]byte(`{"type":"flow"}`))
	}
	if got, want := len(client.flow), cap(client.flow); got != want {
		t.Fatalf("slow client flow queue length = %d, want %d", got, want)
	}

	alert := NewAlertMessage("important", "possible_port_scan", SeverityWarning, "192.0.2.1", "198.51.100.1", 15)
	data, err := json.Marshal(alert)
	if err != nil {
		t.Fatal(err)
	}
	hub.deliverControl(data)

	data, ok := <-client.control
	if !ok {
		t.Fatal("slow client was disconnected when its flow queue filled")
	}
	if !bytes.Contains(data, []byte(`"type":"alert"`)) {
		t.Fatalf("expected alert on control queue, got %s", data)
	}
}

func TestLossyLiveMessageClassification(t *testing.T) {
	if !isLossyLiveMessage(NewFlowMessage("a", "b", 1, 2, "TCP", 1, 1)) {
		t.Fatal("flow messages must be lossy under backpressure")
	}
	if !isLossyLiveMessage(NewDNSMessage("a", "example.test", "A", nil)) {
		t.Fatal("DNS visibility messages must not block control delivery")
	}
	if isLossyLiveMessage(NewAlertMessage("id", "possible_port_scan", SeverityWarning, "a", "b", 1)) {
		t.Fatal("alerts must use reliable control delivery")
	}
	if isLossyLiveMessage(NewStatusMessage("local", "iface", "session", true)) {
		t.Fatal("status messages must use reliable control delivery")
	}
}
