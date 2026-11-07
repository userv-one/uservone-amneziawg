package device

import (
	"bytes"
	"testing"
)

func TestReframeOutboundPacket(t *testing.T) {
	t.Parallel()

	payload := []byte("userv.one-payload")
	for _, test := range []struct {
		name      string
		oldOffset int
		newOffset int
	}{
		{name: "unchanged", oldOffset: 16, newOffset: 16},
		{name: "forward overlapping", oldOffset: 16, newOffset: 41},
		{name: "backward overlapping", oldOffset: 41, newOffset: 16},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			buffer := make([]byte, 256)
			copy(buffer[test.oldOffset:], payload)
			packet, ok := reframeOutboundPacket(buffer, len(payload), test.oldOffset, test.newOffset)
			if !ok {
				t.Fatal("valid packet was rejected")
			}
			if !bytes.Equal(packet, payload) {
				t.Fatalf("packet = %q, want %q", packet, payload)
			}
			if !bytes.Equal(buffer[test.newOffset:test.newOffset+len(payload)], payload) {
				t.Fatal("packet was not moved to the requested offset")
			}
		})
	}
}

func TestReframeOutboundPacketRejectsInvalidBounds(t *testing.T) {
	t.Parallel()

	buffer := make([]byte, 64)
	for _, test := range []struct {
		name                       string
		size, oldOffset, newOffset int
	}{
		{name: "negative size", size: -1, oldOffset: 0, newOffset: 0},
		{name: "negative old offset", size: 1, oldOffset: -1, newOffset: 0},
		{name: "negative new offset", size: 1, oldOffset: 0, newOffset: -1},
		{name: "source overflow", size: 32, oldOffset: 40, newOffset: 0},
		{name: "destination overflow", size: 32, oldOffset: 0, newOffset: 40},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, ok := reframeOutboundPacket(buffer, test.size, test.oldOffset, test.newOffset); ok {
				t.Fatal("invalid bounds were accepted")
			}
		})
	}
}
