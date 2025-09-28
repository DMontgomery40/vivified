package vivified

import "testing"

func TestClientMethodsExist(t *testing.T) {
    c := NewClient("http://localhost:8000", "")
    if c == nil {
        t.Fatal("client nil")
    }
    // Just ensure methods compile and can be called with zero env
    _ = c.Subscribe("DevHello", func(m map[string]any) {})
}

