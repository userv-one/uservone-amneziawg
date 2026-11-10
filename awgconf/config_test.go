package awgconf

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/userv-one/uservone-amneziawg/v3/conn/bindtest"
	"github.com/userv-one/uservone-amneziawg/v3/device"
	"github.com/userv-one/uservone-amneziawg/v3/profile"
	"github.com/userv-one/uservone-amneziawg/v3/tun/tuntest"
)

func testKey(t *testing.T, value byte) string {
	t.Helper()
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{value}, 32))
}

func testHexKey(t *testing.T) string {
	t.Helper()
	return strings.Repeat("22", 32)
}

func validConfig(t *testing.T) string {
	t.Helper()
	return `[Interface]
PrivateKey = ` + testKey(t, 1) + `
Address = 10.20.0.1/32
ListenPort = 51820
FwMark = 51820
MTU = 1420
Table = auto
SaveConfig = false
PreUp = true # scripts may contain hashes
PostDown = true
Jc = 6
Jmin = 64
Jmax = 192
S1 = 32
S2 = 32
S3 = 32
S4 = 32
H1 = 1001-1999
H2 = 2001-2999
H3 = 3001-3999
H4 = 4001-4999
I1 = <b 0xdead><r 8>
HeaderProtectionKey = ` + testHexKey(t) + `
ContentPaddingAddition = 16-96
RekeyAfterTime = 110-120
RekeyTimeout = 5-7
RejectAfterTime = 180-200
KeepaliveTimeout = 10-12
MaxHandshakeAttempts = 18-20
RandomTrailers = false
DisableCookies = false

[Peer]
PublicKey = ` + testKey(t, 3) + `
PresharedKey = ` + testKey(t, 4) + `
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = vpn.example.com:51820
PersistentKeepalive = 25-35
`
}

func TestValidateAcceptsAWGQuickConfig(t *testing.T) {
	t.Parallel()
	if err := Validate(strings.NewReader(validConfig(t))); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
}

func TestValidateRejectsInvalidConfigsWithoutLeakingKeys(t *testing.T) {
	t.Parallel()

	secret := testKey(t, 9)
	tests := []struct {
		name   string
		config string
	}{
		{name: "empty", config: ""},
		{name: "missing interface", config: "[Peer]\nPublicKey = " + testKey(t, 3)},
		{name: "missing private key", config: "[Interface]\nAddress = 10.0.0.1/32\n"},
		{name: "unknown section", config: "[Unknown]\n"},
		{name: "unknown interface key", config: "[Interface]\nPrivateKey = " + secret + "\nUnknown = true\n"},
		{name: "unknown peer key", config: validConfig(t) + "Unknown = true\n"},
		{name: "invalid private key", config: "[Interface]\nPrivateKey = top-secret-value\n"},
		{name: "zero private key", config: "[Interface]\nPrivateKey = " + testKey(t, 0) + "\n"},
		{name: "junk amplification", config: strings.Replace(validConfig(t), "Jc = 6", "Jc = 129", 1)},
		{name: "reversed junk range", config: strings.Replace(validConfig(t), "Jmin = 64", "Jmin = 193", 1)},
		{name: "overlapping headers", config: strings.Replace(validConfig(t), "H2 = 2001-2999", "H2 = 1001-1999", 1)},
		{name: "short nonce padding", config: strings.Replace(validConfig(t), "S4 = 32", "S4 = 8", 1)},
		{name: "invalid signature", config: strings.Replace(validConfig(t), "I1 = <b 0xdead><r 8>", "I1 = <r -1>", 1)},
		{name: "invalid allowed IP", config: strings.Replace(validConfig(t), "0.0.0.0/0", "all-networks", 1)},
		{name: "invalid endpoint", config: strings.Replace(validConfig(t), "vpn.example.com:51820", "missing-port", 1)},
		{name: "invalid header key", config: strings.Replace(validConfig(t), testHexKey(t), "bad", 1)},
		{name: "missing peer public key", config: validConfig(t) + "\n[Peer]\nAllowedIPs = 10.0.0.2/32\n"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := Validate(strings.NewReader(test.config))
			if err == nil {
				t.Fatal("invalid config unexpectedly succeeded")
			}
			if strings.Contains(err.Error(), "top-secret-value") || strings.Contains(err.Error(), secret) {
				t.Fatalf("validation error leaks key material: %v", err)
			}
		})
	}
}

func TestValidateAcceptsCompatQuickValues(t *testing.T) {
	t.Parallel()
	config := validConfig(t)
	config = strings.Replace(config, "[Interface]", "[Interface] # awg-quick", 1)
	config = strings.Replace(config, "[Peer]", "[Peer] ; peer", 1)
	config = strings.Replace(config, "Address = 10.20.0.1/32", "Address = 10.20.0.1", 1)
	config = strings.Replace(config, "FwMark = 51820", "FwMark = 0xca6c", 1)
	if err := Validate(strings.NewReader(config)); err != nil {
		t.Fatalf("compatible wg-quick values rejected: %v", err)
	}
}

func TestValidateAcceptsBase64HeaderProtectionKey(t *testing.T) {
	t.Parallel()
	config := strings.Replace(validConfig(t), testHexKey(t), testKey(t, 2), 1)
	if err := Validate(strings.NewReader(config)); err != nil {
		t.Fatalf("awg-quick base64 HeaderProtectionKey rejected: %v", err)
	}
}

func TestHeaderProtectionKeyMatchesRuntimeUAPI(t *testing.T) {
	key := testHexKey(t)
	config := validConfig(t)
	if err := Validate(strings.NewReader(config)); err != nil {
		t.Fatalf("check-config rejected hex HeaderProtectionKey: %v", err)
	}

	settings := profile.Balanced()
	settings.HeaderProtectionKey = key
	uapi, err := settings.UAPI(false)
	if err != nil {
		t.Fatal(err)
	}
	binds := bindtest.NewChannelBinds()
	tun := tuntest.NewChannelTUN()
	dev := device.NewDevice(tun.TUN(), binds[0], device.NewLogger(device.LogLevelSilent, "header-key: "))
	defer dev.Close()
	if err := dev.IpcSet(uapi); err != nil {
		t.Fatalf("runtime UAPI rejected the key accepted by check-config: %v", err)
	}
	state, err := dev.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(state, "header_protection_key="+key+"\n") {
		t.Fatalf("runtime state is missing the shared key:\n%s", state)
	}
}

func TestValidateRejectsDuplicatePeers(t *testing.T) {
	t.Parallel()
	config := validConfig(t) + "\n[Peer]\nPublicKey = " + testKey(t, 3) + "\nAllowedIPs = 10.0.0.3/32\n"
	if err := Validate(strings.NewReader(config)); err == nil {
		t.Fatal("duplicate peer public key unexpectedly succeeded")
	}
}
