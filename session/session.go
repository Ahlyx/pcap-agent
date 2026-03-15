package session

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

// Session holds metadata for a single capture session.
type Session struct {
	ID        string
	Mode      string
	Interface string
	StartTime time.Time
}

// NewSession creates a new Session with a random ID.
func NewSession(mode, iface string) *Session {
	return &Session{
		ID:        GenerateID(),
		Mode:      mode,
		Interface: iface,
		StartTime: time.Now(),
	}
}

// GenerateID returns an 8-character random hex string.
func GenerateID() string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("session: crypto/rand unavailable: %v", err))
	}
	return hex.EncodeToString(b)
}

// String returns a human-readable description of the session.
func (s *Session) String() string {
	return fmt.Sprintf("session %s | mode: %s | iface: %s", s.ID, s.Mode, s.Interface)
}
