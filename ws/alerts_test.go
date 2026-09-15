package ws

import (
	"encoding/json"
	"testing"
	"time"
)

func TestAlertEmitterSuppressesAndAllowsEscalation(t *testing.T) {
	var delivered int
	e := NewAlertEmitter(func(interface{}) { delivered++ }, time.Minute)
	base := time.Unix(100, 0)
	alert := NewAlertMessage("same", "periodic_connection", SeverityNotice, "a", "b", 1)
	alert.Timestamp = base
	if !e.Emit(alert) || delivered != 1 {
		t.Fatal("first alert was not delivered")
	}
	duplicate := *alert
	duplicate.Timestamp = base.Add(time.Second)
	if e.Emit(&duplicate) || delivered != 1 {
		t.Fatal("duplicate inside cooldown delivered")
	}
	escalated := duplicate
	escalated.Severity = SeverityWarning
	if !e.Emit(&escalated) || delivered != 2 {
		t.Fatal("severity escalation suppressed")
	}
	later := duplicate
	later.Timestamp = base.Add(2 * time.Minute)
	if !e.Emit(&later) || delivered != 3 {
		t.Fatal("alert did not re-emit after cooldown")
	}
	other := duplicate
	other.ID = "other"
	if !e.Emit(&other) || delivered != 4 {
		t.Fatal("different alert IDs were not independent")
	}
}

func TestAlertSchemaIncludesIdentitySeverityAndTimestamp(t *testing.T) {
	for _, severity := range []AlertSeverity{SeverityInfo, SeverityNotice, SeverityWarning, SeverityCritical} {
		msg := NewAlertMessage("id", "tcp_anomaly", severity, "a", "b", 2)
		msg.Subtype = "tcp_reset"
		encoded, err := json.Marshal(msg)
		if err != nil {
			t.Fatal(err)
		}
		var decoded map[string]interface{}
		if err := json.Unmarshal(encoded, &decoded); err != nil {
			t.Fatal(err)
		}
		for _, field := range []string{"type", "id", "alert_type", "severity", "timestamp", "subtype"} {
			if _, ok := decoded[field]; !ok {
				t.Fatalf("%s absent from %s", field, encoded)
			}
		}
	}
}
