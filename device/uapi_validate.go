package device

import (
	"errors"
	"fmt"
)

// validate checks a complete candidate configuration before any device state is
// changed. UAPI updates are incremental, so validation belongs after parsing.
func (d *ipcSetDevice) validate() error {
	if d.junk.count > MaxJunkPackets {
		return fmt.Errorf("jc=%d exceeds limit %d", d.junk.count, MaxJunkPackets)
	}
	if d.junk.max > MaxJunkPacketSize {
		return fmt.Errorf("jmax=%d exceeds UDP payload limit %d", d.junk.max, MaxJunkPacketSize)
	}
	if d.junk.min > d.junk.max {
		return fmt.Errorf("jmin=%d must not exceed jmax=%d", d.junk.min, d.junk.max)
	}

	headers := []UintRange{d.headers.init, d.headers.response, d.headers.cookie, d.headers.transport}
	for i := 0; i < len(headers); i++ {
		for j := i + 1; j < len(headers); j++ {
			if headers[i].Overlap(headers[j]) {
				return errors.New("headers must not overlap")
			}
		}
	}

	paddings := []struct {
		name        string
		value       uint32
		messageSize int
	}{
		{name: "s1", value: d.paddings.init, messageSize: MessageInitiationSize},
		{name: "s2", value: d.paddings.response, messageSize: MessageResponseSize},
		{name: "s3", value: d.paddings.cookie, messageSize: MessageCookieReplySize},
		{name: "s4", value: d.paddings.transport, messageSize: MessageTransportSize},
	}
	for _, padding := range paddings {
		if uint64(padding.value)+uint64(padding.messageSize) > uint64(MaxSegmentSize) {
			return fmt.Errorf(
				"%s=%d leaves insufficient room for its %d-byte message in the %d-byte packet buffer",
				padding.name, padding.value, padding.messageSize, MaxSegmentSize,
			)
		}
		if !d.headerProtectionKey.IsZero() && padding.value < HeaderCipherNonceSize {
			return fmt.Errorf("%s must be at least %d to use header protection", padding.name, HeaderCipherNonceSize)
		}
	}
	return nil
}
