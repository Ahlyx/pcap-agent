package ws

import (
	"sync"
	"time"
)

type emittedAlert struct {
	at       time.Time
	severity AlertSeverity
}

// AlertEmitter is the one route for alert-like messages. It suppresses equal
// alert IDs during a cooldown but immediately permits a severity increase.
type AlertEmitter struct {
	mu        sync.Mutex
	broadcast func(interface{})
	cooldown  time.Duration
	seen      map[string]emittedAlert
}

func NewAlertEmitter(broadcast func(interface{}), cooldown time.Duration) *AlertEmitter {
	return &AlertEmitter{broadcast: broadcast, cooldown: cooldown, seen: make(map[string]emittedAlert)}
}
func (e *AlertEmitter) Emit(alert *AlertMessage) bool {
	if alert.Timestamp.IsZero() {
		alert.Timestamp = time.Now()
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	for id, prior := range e.seen {
		if alert.Timestamp.Sub(prior.at) > 2*e.cooldown {
			delete(e.seen, id)
		}
	}
	prior, exists := e.seen[alert.ID]
	if exists && alert.Timestamp.Sub(prior.at) < e.cooldown && alert.Severity.Rank() <= prior.severity.Rank() {
		return false
	}
	e.seen[alert.ID] = emittedAlert{at: alert.Timestamp, severity: alert.Severity}
	e.broadcast(alert)
	return true
}
