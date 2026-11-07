// Package profile provides bounded, protocol-compatible AmneziaWG presets.
package profile

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/userv-one/uservone-amneziawg/v3/device"
)

const maxContentPadding = 512

// Profile describes shared AWG wire settings and optional client-side junk.
// Private keys and peer settings deliberately do not belong to a profile.
type Profile struct {
	JunkCount              uint32
	JunkMin                uint32
	JunkMax                uint32
	InitiationPadding      uint32
	ResponsePadding        uint32
	CookiePadding          uint32
	TransportPadding       uint32
	InitiationHeader       string
	ResponseHeader         string
	CookieHeader           string
	TransportHeader        string
	ContentPaddingAddition string
	RandomTrailers         bool
	DisableCookies         bool
	HeaderProtectionKey    string
}

// Balanced varies packet sizes and headers without large bandwidth overhead.
func Balanced() Profile {
	return Profile{
		JunkCount: 6, JunkMin: 64, JunkMax: 192,
		InitiationPadding: 32, ResponsePadding: 32, CookiePadding: 32, TransportPadding: 32,
		InitiationHeader: "1001-1999", ResponseHeader: "2001-2999",
		CookieHeader: "3001-3999", TransportHeader: "4001-4999",
		ContentPaddingAddition: "16-96",
	}
}

// LowBandwidth reduces junk and padding for constrained links.
func LowBandwidth() Profile {
	return Profile{
		JunkCount: 3, JunkMin: 32, JunkMax: 64,
		InitiationPadding: 16, ResponsePadding: 16, CookiePadding: 16, TransportPadding: 16,
		InitiationHeader: "1001-1099", ResponseHeader: "2001-2099",
		CookieHeader: "3001-3099", TransportHeader: "4001-4099",
		ContentPaddingAddition: "0-32",
	}
}

// GenerateHeaderProtectionKey returns a fresh 256-bit key encoded for UAPI.
func GenerateHeaderProtectionKey() (string, error) {
	var key [device.HeaderCipherKeySize]byte
	if _, err := rand.Read(key[:]); err != nil {
		return "", fmt.Errorf("generate header protection key: %w", err)
	}
	return hex.EncodeToString(key[:]), nil
}

func (p Profile) Validate() error {
	if p.JunkCount > device.MaxJunkPackets {
		return fmt.Errorf("junk count exceeds %d", device.MaxJunkPackets)
	}
	if p.JunkMax > device.MaxJunkPacketSize || p.JunkMin > p.JunkMax {
		return errors.New("invalid junk packet size range")
	}
	if p.DisableCookies {
		return errors.New("cookie replies are required by userv.one profiles")
	}
	if p.RandomTrailers && p.ContentPaddingAddition != "" {
		return errors.New("random trailers and content padding are mutually exclusive in a profile")
	}

	headers := make([]device.UintRange, 4)
	for index, value := range []string{p.InitiationHeader, p.ResponseHeader, p.CookieHeader, p.TransportHeader} {
		if err := headers[index].FromString(value); err != nil {
			return fmt.Errorf("invalid H%d: %w", index+1, err)
		}
		for previous := 0; previous < index; previous++ {
			if headers[previous].Overlap(headers[index]) {
				return fmt.Errorf("H%d and H%d overlap", previous+1, index+1)
			}
		}
	}

	var headerKey device.HeaderCipherKey
	if p.HeaderProtectionKey != "" {
		if err := headerKey.FromHex(p.HeaderProtectionKey); err != nil || headerKey.IsZero() {
			return errors.New("header protection key must be a non-zero 32-byte hexadecimal value")
		}
	}
	paddings := []struct {
		name        string
		value       uint32
		messageSize int
	}{
		{"S1", p.InitiationPadding, device.MessageInitiationSize},
		{"S2", p.ResponsePadding, device.MessageResponseSize},
		{"S3", p.CookiePadding, device.MessageCookieReplySize},
		{"S4", p.TransportPadding, device.MessageTransportSize},
	}
	for _, padding := range paddings {
		if uint64(padding.value)+uint64(padding.messageSize) > uint64(device.MaxSegmentSize) {
			return fmt.Errorf("%s exceeds the packet buffer", padding.name)
		}
		if !headerKey.IsZero() && padding.value < device.HeaderCipherNonceSize {
			return fmt.Errorf("%s must be at least %d with header protection", padding.name, device.HeaderCipherNonceSize)
		}
	}

	if p.ContentPaddingAddition != "" {
		var addition device.UintRange
		if err := addition.FromString(p.ContentPaddingAddition); err != nil {
			return fmt.Errorf("invalid content padding: %w", err)
		}
		if addition.Hi() > maxContentPadding {
			return fmt.Errorf("content padding exceeds %d bytes", maxContentPadding)
		}
	}
	return nil
}

// UAPI renders settings accepted by awg set and Device.IpcSet. Junk packets are
// emitted only for clients; shared headers and paddings are emitted on both sides.
func (p Profile) UAPI(client bool) (string, error) {
	if err := p.Validate(); err != nil {
		return "", err
	}
	var output strings.Builder
	if client && p.JunkCount > 0 {
		fmt.Fprintf(&output, "jc=%d\njmin=%d\njmax=%d\n", p.JunkCount, p.JunkMin, p.JunkMax)
	}
	fmt.Fprintf(&output, "s1=%d\ns2=%d\ns3=%d\ns4=%d\n",
		p.InitiationPadding, p.ResponsePadding, p.CookiePadding, p.TransportPadding)
	fmt.Fprintf(&output, "h1=%s\nh2=%s\nh3=%s\nh4=%s\n",
		p.InitiationHeader, p.ResponseHeader, p.CookieHeader, p.TransportHeader)
	if p.ContentPaddingAddition != "" {
		fmt.Fprintf(&output, "content_padding_addition=%s\n", p.ContentPaddingAddition)
	}
	fmt.Fprintf(&output, "random_trailers=%t\ndisable_cookies=%t\n", p.RandomTrailers, p.DisableCookies)
	if p.HeaderProtectionKey != "" {
		fmt.Fprintf(&output, "header_protection_key=%s\n", p.HeaderProtectionKey)
	}
	return output.String(), nil
}
