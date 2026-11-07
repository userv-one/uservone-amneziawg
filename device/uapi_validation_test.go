package device

import (
	"fmt"
	"strings"
	"testing"
)

func newAWGValidationTestDevice() *Device {
	device := &Device{log: NewLogger(LogLevelSilent, "test: ")}
	for header, value := range map[*AtomicUintRange]uint32{
		&device.headers.init:      MessageInitiationType,
		&device.headers.response:  MessageResponseType,
		&device.headers.cookie:    MessageCookieReplyType,
		&device.headers.transport: MessageTransportType,
	} {
		var rang UintRange
		rang.FromUint32(value, value)
		header.Store(rang)
	}
	return device
}

func TestIpcSetRejectsUnsafeAWGParameters(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		config string
	}{
		{name: "too many junk packets", config: "jc=129"},
		{name: "junk packet too large", config: "jmax=65508"},
		{name: "reversed junk sizes", config: "jmin=128\njmax=127"},
		{name: "initiation padding overflows buffer", config: "s1=65535"},
		{name: "response padding overflows buffer", config: "s2=65535"},
		{name: "cookie padding overflows buffer", config: "s3=65535"},
		{name: "transport padding overflows buffer", config: "s4=65535"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			device := newAWGValidationTestDevice()
			if err := device.IpcSet(test.config + "\n"); err == nil {
				t.Fatalf("IpcSet(%q) unexpectedly succeeded", test.config)
			}
		})
	}
}

func TestIpcSetAcceptsBoundedAWGParameters(t *testing.T) {
	t.Parallel()

	device := newAWGValidationTestDevice()
	config := "jc=8\njmin=32\njmax=128\ns1=32\ns2=32\ns3=32\ns4=32\n"
	if err := device.IpcSet(config); err != nil {
		t.Fatalf("valid AWG config rejected: %v", err)
	}
	if got := device.junk.count.Load(); got != 8 {
		t.Fatalf("junk count = %d, want 8", got)
	}
	if got := device.junk.min.Load(); got != 32 {
		t.Fatalf("junk min = %d, want 32", got)
	}
	if got := device.junk.max.Load(); got != 128 {
		t.Fatalf("junk max = %d, want 128", got)
	}
}

func TestInvalidAWGConfigDoesNotMutateDevice(t *testing.T) {
	t.Parallel()

	device := newAWGValidationTestDevice()
	if err := device.IpcSet("jc=8\njmin=32\njmax=128\n"); err != nil {
		t.Fatal(err)
	}
	if err := device.IpcSet("jc=64\njmin=512\njmax=128\n"); err == nil {
		t.Fatal("invalid junk range unexpectedly succeeded")
	}
	if got := device.junk.count.Load(); got != 8 {
		t.Fatalf("junk count changed to %d after rejected update", got)
	}
	if got := device.junk.min.Load(); got != 32 {
		t.Fatalf("junk min changed to %d after rejected update", got)
	}
	if got := device.junk.max.Load(); got != 128 {
		t.Fatalf("junk max changed to %d after rejected update", got)
	}
}

func TestJunkPacketsHonorFixedSize(t *testing.T) {
	t.Parallel()

	device := newAWGValidationTestDevice()
	if err := device.IpcSet("jc=3\njmin=64\njmax=64\n"); err != nil {
		t.Fatal(err)
	}
	packets := device.JunkPackets()
	if len(packets) != 3 {
		t.Fatalf("got %d junk packets, want 3", len(packets))
	}
	for index, packet := range packets {
		if len(packet) != 64 {
			t.Errorf("packet %d has length %d, want 64", index, len(packet))
		}
	}
}

func TestUintRangePickOneSupportsFullUint32Range(t *testing.T) {
	t.Parallel()

	var rang UintRange
	if err := rang.FromString("0-4294967295"); err != nil {
		t.Fatal(err)
	}
	seen := make(map[uint32]struct{})
	for range 16 {
		seen[rang.PickOne()] = struct{}{}
	}
	if len(seen) < 2 {
		t.Fatal("full uint32 range collapsed to a single value")
	}
}

func TestPaddingLimitErrorNamesMessage(t *testing.T) {
	t.Parallel()

	device := newAWGValidationTestDevice()
	for index, key := range []string{"s1", "s2", "s3", "s4"} {
		t.Run(key, func(t *testing.T) {
			err := device.IpcSet(fmt.Sprintf("%s=65535\n", key))
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), key) {
				t.Fatalf("error %v does not identify %s", err, key)
			}
			_ = index
		})
	}
}
