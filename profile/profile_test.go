package profile_test

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/userv-one/uservone-amneziawg/v3/conn/bindtest"
	"github.com/userv-one/uservone-amneziawg/v3/device"
	"github.com/userv-one/uservone-amneziawg/v3/profile"
	"github.com/userv-one/uservone-amneziawg/v3/tun/tuntest"
)

func TestBalancedProfileGeneratesClientAndServerUAPI(t *testing.T) {
	t.Parallel()

	profile := profile.Balanced()
	client, err := profile.UAPI(true)
	if err != nil {
		t.Fatal(err)
	}
	for _, directive := range []string{
		"jc=6\n", "jmin=64\n", "jmax=192\n",
		"s1=32\n", "s2=32\n", "s3=32\n", "s4=32\n",
		"h1=1001-1999\n", "h2=2001-2999\n", "h3=3001-3999\n", "h4=4001-4999\n",
		"content_padding_addition=16-96\n", "disable_cookies=false\n",
	} {
		if !strings.Contains(client, directive) {
			t.Errorf("client UAPI does not contain %q:\n%s", directive, client)
		}
	}

	server, err := profile.UAPI(false)
	if err != nil {
		t.Fatal(err)
	}
	for _, directive := range []string{"jc=", "jmin=", "jmax="} {
		if strings.Contains(server, directive) {
			t.Errorf("server UAPI unexpectedly contains %q", directive)
		}
	}
	if !strings.Contains(server, "h1=1001-1999\n") {
		t.Fatal("server is missing the shared header configuration")
	}
}

func TestProfileHeaderProtection(t *testing.T) {
	t.Parallel()

	first, err := profile.GenerateHeaderProtectionKey()
	if err != nil {
		t.Fatal(err)
	}
	second, err := profile.GenerateHeaderProtectionKey()
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 64 || first == second {
		t.Fatalf("generated keys are invalid or repeated: len=%d equal=%v", len(first), first == second)
	}
	if _, err := hex.DecodeString(first); err != nil {
		t.Fatalf("generated key is not hexadecimal: %v", err)
	}

	config := profile.Balanced()
	config.HeaderProtectionKey = first
	uapi, err := config.UAPI(true)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(uapi, "header_protection_key="+first+"\n") {
		t.Fatal("UAPI is missing header protection key")
	}
}

func TestProfileRejectsUnsafeValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*profile.Profile)
	}{
		{name: "junk amplification", mutate: func(p *profile.Profile) { p.JunkCount = 129 }},
		{name: "reversed junk range", mutate: func(p *profile.Profile) { p.JunkMin = 200 }},
		{name: "oversized padding", mutate: func(p *profile.Profile) { p.TransportPadding = 65535 }},
		{name: "overlapping headers", mutate: func(p *profile.Profile) { p.ResponseHeader = p.InitiationHeader }},
		{name: "cookies disabled", mutate: func(p *profile.Profile) { p.DisableCookies = true }},
		{name: "ambiguous padding", mutate: func(p *profile.Profile) { p.RandomTrailers = true }},
		{name: "invalid header key", mutate: func(p *profile.Profile) { p.HeaderProtectionKey = "secret" }},
		{name: "zero header key", mutate: func(p *profile.Profile) { p.HeaderProtectionKey = strings.Repeat("0", 64) }},
		{name: "short nonce padding", mutate: func(p *profile.Profile) {
			p.HeaderProtectionKey = strings.Repeat("11", 32)
			p.TransportPadding = 8
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			config := profile.Balanced()
			test.mutate(&config)
			if _, err := config.UAPI(true); err == nil {
				t.Fatal("unsafe profile unexpectedly succeeded")
			}
		})
	}
}

func TestProfilesAreAcceptedByProtocolCore(t *testing.T) {
	for _, config := range []profile.Profile{profile.Balanced(), profile.LowBandwidth()} {
		uapi, err := config.UAPI(true)
		if err != nil {
			t.Fatal(err)
		}
		binds := bindtest.NewChannelBinds()
		tun := tuntest.NewChannelTUN()
		dev := device.NewDevice(tun.TUN(), binds[0], device.NewLogger(device.LogLevelSilent, "profile-test: "))
		if err := dev.IpcSet(uapi); err != nil {
			dev.Close()
			t.Fatalf("core rejected generated profile: %v", err)
		}
		dev.Close()
	}
}
