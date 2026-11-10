package device

import (
	"errors"
	"fmt"
)

// AWGParameters is the shareable subset of AmneziaWG settings used by both
// UAPI application and awg-quick configuration validation.
type AWGParameters struct {
	JunkCount           uint32
	JunkMin             uint32
	JunkMax             uint32
	InitiationPadding   uint32
	ResponsePadding     uint32
	CookiePadding       uint32
	TransportPadding    uint32
	InitiationHeader    UintRange
	ResponseHeader      UintRange
	CookieHeader        UintRange
	TransportHeader     UintRange
	HeaderProtectionKey HeaderCipherKey
}

// Validate rejects unsafe or internally inconsistent AWG settings.
func (p AWGParameters) Validate() error {
	if p.JunkCount > MaxJunkPackets {
		return fmt.Errorf("jc=%d exceeds limit %d", p.JunkCount, MaxJunkPackets)
	}
	if p.JunkMax > MaxJunkPacketSize {
		return fmt.Errorf("jmax=%d exceeds UDP payload limit %d", p.JunkMax, MaxJunkPacketSize)
	}
	if p.JunkMin > p.JunkMax {
		return fmt.Errorf("jmin=%d must not exceed jmax=%d", p.JunkMin, p.JunkMax)
	}

	headers := []UintRange{p.InitiationHeader, p.ResponseHeader, p.CookieHeader, p.TransportHeader}
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
		{name: "s1", value: p.InitiationPadding, messageSize: MessageInitiationSize},
		{name: "s2", value: p.ResponsePadding, messageSize: MessageResponseSize},
		{name: "s3", value: p.CookiePadding, messageSize: MessageCookieReplySize},
		{name: "s4", value: p.TransportPadding, messageSize: MessageTransportSize},
	}
	for _, padding := range paddings {
		if uint64(padding.value)+uint64(padding.messageSize) > uint64(MaxSegmentSize) {
			return fmt.Errorf(
				"%s=%d leaves insufficient room for its %d-byte message in the %d-byte packet buffer",
				padding.name, padding.value, padding.messageSize, MaxSegmentSize,
			)
		}
		if !p.HeaderProtectionKey.IsZero() && padding.value < HeaderCipherNonceSize {
			return fmt.Errorf("%s must be at least %d to use header protection", padding.name, HeaderCipherNonceSize)
		}
	}
	return nil
}

// ValidateObfuscationSpec validates an I1-I5 signature chain without applying it.
func ValidateObfuscationSpec(spec string) error {
	_, err := newObfChain(spec)
	return err
}
