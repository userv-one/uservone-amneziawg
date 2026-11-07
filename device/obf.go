package device

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const maxObfPacketSize = 65507 // largest payload in a UDP datagram

type obfBuilder func(val string) (obf, error)

var obfBuilders = map[string]obfBuilder{
	"b":  newBytesObf,
	"t":  newTimestampObf,
	"r":  newRandObf,
	"rc": newRandCharObf,
	"rd": newRandDigitsObf,
	"d":  newDataObf,
	"ds": newDataStringObf,
	"dz": newDataSizeObf,
}

type obf interface {
	Obfuscate(dst, src []byte)
	Deobfuscate(dst, src []byte) bool
	ObfuscatedLen(srcLen int) int
	DeobfuscatedLen(srcLen int) int
}

type obfChain struct {
	Spec string
	obfs []obf
}

func parseObfLength(val string, min, max int) (int, error) {
	length, err := strconv.Atoi(val)
	if err != nil {
		return 0, err
	}
	if length < min || length > max {
		return 0, fmt.Errorf("length must be between %d and %d", min, max)
	}
	return length, nil
}

func newObfChain(spec string) (*obfChain, error) {
	var (
		obfs          []obf
		errs          []error
		payloadFields int
		totalLen      int
	)

	remaining := spec
	for remaining != "" {
		if remaining[0] != '<' {
			errs = append(errs, fmt.Errorf("unexpected text near %q", remaining))
			break
		}

		end := strings.IndexByte(remaining, '>')
		if end == -1 {
			errs = append(errs, errors.New("missing enclosing >"))
			break
		}

		tag := remaining[1:end]
		parts := strings.Fields(tag)
		if len(parts) == 0 {
			errs = append(errs, errors.New("empty tag"))
			remaining = remaining[end+1:]
			continue
		}

		key := parts[0]
		builder, ok := obfBuilders[key]
		if !ok {
			errs = append(errs, fmt.Errorf("unknown tag <%s>", key))
			remaining = remaining[end+1:]
			continue
		}

		expectedParts := 1
		switch key {
		case "b", "r", "rc", "rd", "dz":
			expectedParts = 2
		}
		if len(parts) != expectedParts {
			errs = append(errs, fmt.Errorf("tag <%s> has wrong number of arguments", key))
			remaining = remaining[end+1:]
			continue
		}

		val := ""
		if len(parts) > 1 {
			val = parts[1]
		}

		o, err := builder(val)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to build <%s>: %w", key, err))
			remaining = remaining[end+1:]
			continue
		}
		if key == "d" || key == "ds" {
			payloadFields++
			if payloadFields > 1 {
				errs = append(errs, errors.New("only one data-bearing tag is allowed"))
				remaining = remaining[end+1:]
				continue
			}
		}
		obfLen := o.ObfuscatedLen(0)
		if obfLen < 0 || totalLen > maxObfPacketSize-obfLen {
			errs = append(errs, fmt.Errorf("obfuscated packet exceeds %d bytes", maxObfPacketSize))
			remaining = remaining[end+1:]
			continue
		}
		totalLen += obfLen
		obfs = append(obfs, o)
		remaining = remaining[end+1:]
	}

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	if len(obfs) == 0 {
		return nil, nil
	}

	return &obfChain{
		Spec: spec,
		obfs: obfs,
	}, nil
}

func (c *obfChain) Obfuscate(dst, src []byte) {
	written := 0
	for _, o := range c.obfs {
		obfLen := o.ObfuscatedLen(len(src))
		o.Obfuscate(dst[written:written+obfLen], src)
		written += obfLen
	}
}

func (c *obfChain) Deobfuscate(dst, src []byte) bool {
	dynamicLen := len(src) - c.ObfuscatedLen(0)
	if dynamicLen < 0 {
		return false
	}

	written, read := 0, 0

	for _, o := range c.obfs {
		deobfLen := o.DeobfuscatedLen(dynamicLen)
		obfLen := o.ObfuscatedLen(deobfLen)
		if deobfLen < 0 || obfLen < 0 || deobfLen > len(dst)-written || obfLen > len(src)-read {
			return false
		}

		if !o.Deobfuscate(dst[written:written+deobfLen], src[read:read+obfLen]) {
			return false
		}

		written += deobfLen
		read += obfLen
	}

	return read == len(src) && written == len(dst)
}

func (c *obfChain) ObfuscatedLen(n int) int {
	total := 0
	for _, o := range c.obfs {
		total += o.ObfuscatedLen(n)
	}
	return total
}

func (c *obfChain) DeobfuscatedLen(n int) int {
	dynamicLen := n - c.ObfuscatedLen(0)

	total := 0
	for _, o := range c.obfs {
		total += o.DeobfuscatedLen(dynamicLen)
	}
	return total
}
