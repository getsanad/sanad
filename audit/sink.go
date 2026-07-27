package audit

import (
	"encoding/json"
	"io"
	"sync"
)

// JSONLinesSink streams entries as newline-delimited JSON to an io.Writer — a simple,
// widely-ingestable SIEM format (PRD FR-23). Writes are serialized so concurrent appends
// don't interleave. CEF or OTLP sinks can implement the same Sink interface later.
type JSONLinesSink struct {
	mu sync.Mutex
	w  io.Writer
}

// NewJSONLinesSink returns a sink that writes one JSON object per line to w.
func NewJSONLinesSink(w io.Writer) *JSONLinesSink {
	return &JSONLinesSink{w: w}
}

// Write implements Sink.
func (s *JSONLinesSink) Write(e Entry) error {
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.w.Write(append(b, '\n')); err != nil {
		return err
	}
	return nil
}
