package cloudflaresecrets

import (
	"testing"
	"time"
)

func TestInternalDuration(t *testing.T) {
	cases := []struct {
		in   interface{}
		want time.Duration
	}{
		{float64(300), 300 * time.Second}, // JSON round-trip yields float64
		{int64(600), 600 * time.Second},
		{int(90), 90 * time.Second},
		{nil, 0},
		{"600", 0}, // unexpected type → 0, caller leaves lease bound untouched
	}
	for _, c := range cases {
		if got := internalDuration(c.in); got != c.want {
			t.Errorf("internalDuration(%v) = %v, want %v", c.in, got, c.want)
		}
	}
}
