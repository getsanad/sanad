package tooldefs

import (
	"bytes"
	"io"
)

// sseWatcher is a pass-through reader that reassembles server-sent events as they stream by.
//
// It exists because a tools/list POST may be answered with an SSE stream rather than a single
// JSON reply, and an SSE stream must NOT be buffered: the whole point of the transport is that
// the client sees each event when the server writes it, and the gateway sets FlushInterval = -1
// precisely so nothing sits in a buffer. So instead of holding the body, this hands every byte
// straight back to the caller in the same Read that produced it, and reassembles a copy of the
// event data on the side.
//
// The reassembly is deliberately minimal — SSE "data:" lines, concatenated per event, dispatched
// on the blank line that ends it. Field names other than "data" (event, id, retry) are ignored:
// the JSON-RPC payload MCP puts on the stream is in the data field, and nothing else here needs
// to understand the framing.
type sseWatcher struct {
	src io.ReadCloser
	max int64 // bound on a single event's accumulated data
	// onEvent receives each complete event's data. It runs inline on the reading goroutine, so
	// it must be cheap; fingerprinting a tool list is.
	onEvent func(data []byte)
	// onOverflow is called once if an event exceeds max, after which watching stops and the
	// stream is pure pass-through. An unbounded accumulator would turn a hostile stream into a
	// memory exhaustion, which is a worse outcome than an unchecked list.
	onOverflow func()

	line    bytes.Buffer // the partial line carried across Read boundaries
	event   bytes.Buffer // the data field(s) accumulated for the event in progress
	stopped bool
}

// Read passes bytes through untouched and scans a copy.
func (w *sseWatcher) Read(p []byte) (int, error) {
	n, err := w.src.Read(p)
	if n > 0 && !w.stopped {
		w.scan(p[:n])
	}
	return n, err
}

// Close closes the underlying body. Any half-assembled event is dropped: an event the server
// never finished writing is not something to fingerprint.
func (w *sseWatcher) Close() error { return w.src.Close() }

func (w *sseWatcher) scan(b []byte) {
	for len(b) > 0 {
		i := bytes.IndexByte(b, '\n')
		if i < 0 {
			w.line.Write(b)
			if int64(w.line.Len()) > w.max {
				w.overflow()
			}
			return
		}
		w.line.Write(b[:i])
		w.feed(bytes.TrimSuffix(w.line.Bytes(), []byte("\r")))
		w.line.Reset()
		b = b[i+1:]
		if w.stopped {
			return
		}
	}
}

// feed consumes one complete SSE line.
func (w *sseWatcher) feed(line []byte) {
	if len(line) == 0 { // blank line: the event is complete
		if w.event.Len() > 0 {
			data := make([]byte, w.event.Len())
			copy(data, w.event.Bytes())
			w.event.Reset()
			w.onEvent(data)
		}
		return
	}
	rest, ok := bytes.CutPrefix(line, []byte("data:"))
	if !ok {
		return // event:, id:, retry:, or a comment — none of which carry the payload
	}
	if w.event.Len() > 0 {
		w.event.WriteByte('\n') // multiple data: lines in one event are joined by newlines
	}
	// A single leading space after the colon is part of the framing, not the data.
	w.event.Write(bytes.TrimPrefix(rest, []byte(" ")))
	if int64(w.event.Len()) > w.max {
		w.overflow()
	}
}

func (w *sseWatcher) overflow() {
	w.stopped = true
	w.line.Reset()
	w.event.Reset()
	if w.onOverflow != nil {
		w.onOverflow()
	}
}
