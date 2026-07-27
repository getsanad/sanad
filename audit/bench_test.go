package audit

import (
	"context"
	"testing"
)

func BenchmarkAppend(b *testing.B) {
	l := NewHashChainLog(nil) // no sink: measure chain/hash cost only
	e := Entry{Action: "allow", Principal: "p1", Agent: "a1", Server: "demo"}
	ctx := context.Background()
	b.ReportAllocs()
	for b.Loop() {
		if err := l.Append(ctx, e); err != nil {
			b.Fatal(err)
		}
	}
}
