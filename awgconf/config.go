// Package awgconf validates awg-quick INI files without applying them.
package awgconf

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"github.com/userv-one/uservone-amneziawg/v3/device"
)

const (
	maxConfigBytes = 1 << 20
	maxLineBytes   = 64 << 10
)

type parser struct {
	params         device.AWGParameters
	section        string
	line           int
	totalBytes     int
	interfaceSeen  bool
	privateKeySeen bool
	peerSeen       bool
	peerPublicSeen bool
	peerPublicKey  [32]byte
	seenPeers      map[[32]byte]struct{}
}

func defaultParameters() device.AWGParameters {
	var params device.AWGParameters
	params.InitiationHeader.FromUint32(device.MessageInitiationType, device.MessageInitiationType)
	params.ResponseHeader.FromUint32(device.MessageResponseType, device.MessageResponseType)
	params.CookieHeader.FromUint32(device.MessageCookieReplyType, device.MessageCookieReplyType)
	params.TransportHeader.FromUint32(device.MessageTransportType, device.MessageTransportType)
	return params
}

// Validate parses and validates one /etc/amneziawg/*.conf file. It never
// includes private key, public key or preshared key values in returned errors.
func Validate(reader io.Reader) error {
	if reader == nil {
		return errors.New("config reader is nil")
	}
	p := parser{params: defaultParameters(), seenPeers: make(map[[32]byte]struct{})}
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 4096), maxLineBytes)
	for scanner.Scan() {
		p.line++
		p.totalBytes += len(scanner.Bytes()) + 1
		if p.totalBytes > maxConfigBytes {
			return errors.New("config exceeds 1 MiB")
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			closing := strings.IndexByte(line, ']')
			if closing == -1 {
				return p.errorf("malformed section header")
			}
			trailing := strings.TrimSpace(line[closing+1:])
			if trailing != "" && !strings.HasPrefix(trailing, "#") && !strings.HasPrefix(trailing, ";") {
				return p.errorf("unexpected text after section header")
			}
			if err := p.startSection(strings.TrimSpace(line[1:closing])); err != nil {
				return err
			}
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found {
			return p.errorf("expected key = value")
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		if key == "" {
			return p.errorf("empty key")
		}
		var err error
		switch p.section {
		case "interface":
			err = p.interfaceDirective(key, value)
		case "peer":
			err = p.peerDirective(key, value)
		default:
			return p.errorf("directive %q appears before [Interface]", key)
		}
		if err != nil {
			return p.errorf("%s: %v", key, err)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read config: %w", err)
	}
	if err := p.finishPeer(); err != nil {
		return err
	}
	if !p.interfaceSeen {
		return errors.New("missing [Interface] section")
	}
	if !p.privateKeySeen {
		return errors.New("[Interface] is missing PrivateKey")
	}
	if err := p.params.Validate(); err != nil {
		return fmt.Errorf("invalid AWG settings: %w", err)
	}
	return nil
}

// ValidateFile validates a configuration by path without executing directives.
func ValidateFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open config: %w", err)
	}
	defer file.Close()
	if err := Validate(file); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

func (p *parser) errorf(format string, args ...any) error {
	return fmt.Errorf("line %d: %s", p.line, fmt.Sprintf(format, args...))
}

func (p *parser) startSection(section string) error {
	switch strings.ToLower(section) {
	case "interface":
		if p.interfaceSeen || p.peerSeen {
			return p.errorf("duplicate or misplaced [Interface] section")
		}
		p.interfaceSeen = true
		p.section = "interface"
	case "peer":
		if !p.interfaceSeen {
			return p.errorf("[Peer] appears before [Interface]")
		}
		if err := p.finishPeer(); err != nil {
			return err
		}
		p.section = "peer"
		p.peerSeen = true
		p.peerPublicSeen = false
	default:
		return p.errorf("unknown section %q", section)
	}
	return nil
}

func (p *parser) finishPeer() error {
	if p.section != "peer" {
		return nil
	}
	if !p.peerPublicSeen {
		return p.errorf("[Peer] is missing PublicKey")
	}
	if _, duplicate := p.seenPeers[p.peerPublicKey]; duplicate {
		return p.errorf("duplicate peer PublicKey")
	}
	p.seenPeers[p.peerPublicKey] = struct{}{}
	return nil
}

func decodeKey(value string, allowZero bool) ([32]byte, error) {
	var key [32]byte
	var decoded []byte
	var err error
	if len(value) == 64 {
		decoded, err = hex.DecodeString(value)
	} else {
		decoded, err = base64.StdEncoding.Strict().DecodeString(value)
	}
	if err != nil || len(decoded) != len(key) {
		return key, errors.New("expected a base64-encoded or 64-character hexadecimal 32-byte key")
	}
	copy(key[:], decoded)
	if !allowZero && key == ([32]byte{}) {
		return key, errors.New("all-zero key is not allowed")
	}
	return key, nil
}

func parseUint(value string, bits int) (uint64, error) {
	parsed, err := strconv.ParseUint(value, 10, bits)
	if err != nil {
		return 0, errors.New("invalid unsigned integer")
	}
	return parsed, nil
}

func parsePort(value string) error {
	port, err := parseUint(value, 16)
	if err != nil || port == 0 {
		return errors.New("expected a port between 1 and 65535")
	}
	return nil
}

func validateRange(value string) (device.UintRange, error) {
	var result device.UintRange
	if err := result.FromString(value); err != nil {
		return result, errors.New("invalid numeric range")
	}
	return result, nil
}

func validatePrefixList(value string) error {
	if strings.TrimSpace(value) == "" {
		return errors.New("empty network list")
	}
	for _, entry := range strings.Split(value, ",") {
		entry = strings.TrimSpace(entry)
		if _, err := netip.ParsePrefix(entry); err != nil {
			return errors.New("invalid IP prefix")
		}
	}
	return nil
}

func validateAddressList(value string) error {
	if strings.TrimSpace(value) == "" {
		return errors.New("empty address list")
	}
	for _, entry := range strings.Split(value, ",") {
		entry = strings.TrimSpace(entry)
		if _, prefixErr := netip.ParsePrefix(entry); prefixErr != nil {
			if _, addrErr := netip.ParseAddr(entry); addrErr != nil {
				return errors.New("invalid IP address or prefix")
			}
		}
	}
	return nil
}

func validateEndpoint(value string) error {
	host, port, err := net.SplitHostPort(value)
	if err != nil || host == "" || strings.ContainsAny(host, " \t\r\n") {
		return errors.New("expected host:port endpoint")
	}
	return parsePort(port)
}

func (p *parser) interfaceDirective(key, value string) error {
	var err error
	switch key {
	case "privatekey":
		if p.privateKeySeen {
			return errors.New("duplicate PrivateKey")
		}
		_, err = decodeKey(value, false)
		p.privateKeySeen = err == nil
		return err
	case "address":
		return validateAddressList(value)
	case "listenport":
		return parsePort(value)
	case "fwmark":
		if strings.ToLower(value) == "off" {
			return nil
		}
		if strings.HasPrefix(strings.ToLower(value), "0x") {
			_, err = strconv.ParseUint(value[2:], 16, 32)
			return err
		}
		_, err = parseUint(value, 32)
		return err
	case "mtu":
		var mtu uint64
		mtu, err = parseUint(value, 16)
		if err == nil && mtu == 0 {
			return errors.New("MTU must be positive")
		}
		return err
	case "dns", "dnssearch", "table", "preup", "postup", "predown", "postdown":
		return nil
	case "saveconfig":
		_, err = strconv.ParseBool(value)
		return err
	case "jc":
		return p.setUint(key, value, &p.params.JunkCount)
	case "jmin":
		return p.setUint(key, value, &p.params.JunkMin)
	case "jmax":
		return p.setUint(key, value, &p.params.JunkMax)
	case "s1":
		return p.setUint(key, value, &p.params.InitiationPadding)
	case "s2":
		return p.setUint(key, value, &p.params.ResponsePadding)
	case "s3":
		return p.setUint(key, value, &p.params.CookiePadding)
	case "s4":
		return p.setUint(key, value, &p.params.TransportPadding)
	case "h1":
		p.params.InitiationHeader, err = validateRange(value)
	case "h2":
		p.params.ResponseHeader, err = validateRange(value)
	case "h3":
		p.params.CookieHeader, err = validateRange(value)
	case "h4":
		p.params.TransportHeader, err = validateRange(value)
	case "i1", "i2", "i3", "i4", "i5":
		return device.ValidateObfuscationSpec(value)
	case "headerprotectionkey":
		var decoded [32]byte
		decoded, err = decodeKey(value, false)
		if err == nil {
			copy(p.params.HeaderProtectionKey[:], decoded[:])
		}
	case "contentpaddingaddition", "rekeyaftertime", "rekeytimeout", "rejectaftertime", "keepalivetimeout", "maxhandshakeattempts":
		_, err = validateRange(value)
	case "randomtrailers", "disablecookies":
		_, err = strconv.ParseBool(value)
	default:
		return errors.New("unknown [Interface] directive")
	}
	return err
}

func (p *parser) setUint(_ string, value string, destination *uint32) error {
	parsed, err := parseUint(value, 32)
	if err == nil {
		*destination = uint32(parsed)
	}
	return err
}

func (p *parser) peerDirective(key, value string) error {
	switch key {
	case "publickey":
		if p.peerPublicSeen {
			return errors.New("duplicate PublicKey in [Peer]")
		}
		key, err := decodeKey(value, false)
		if err != nil {
			return err
		}
		p.peerPublicKey = key
		p.peerPublicSeen = true
		return nil
	case "presharedkey":
		_, err := decodeKey(value, true)
		return err
	case "allowedips":
		return validatePrefixList(value)
	case "endpoint":
		return validateEndpoint(value)
	case "persistentkeepalive":
		_, err := validateRange(value)
		return err
	default:
		return errors.New("unknown [Peer] directive")
	}
}
