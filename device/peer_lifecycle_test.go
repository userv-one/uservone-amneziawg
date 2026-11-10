package device

import (
	"crypto/rand"
	"encoding/hex"
	"net/netip"
	"testing"
	"time"

	"github.com/userv-one/uservone-amneziawg/v3/conn/bindtest"
	"github.com/userv-one/uservone-amneziawg/v3/tun/tuntest"
)

func lifecyclePublicKey(t *testing.T) (NoisePublicKey, string) {
	t.Helper()
	var key NoisePublicKey
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal(err)
	}
	return key, hex.EncodeToString(key[:])
}

func lifecycleDevice(t *testing.T) *Device {
	t.Helper()
	binds := bindtest.NewChannelBinds()
	tun := tuntest.NewChannelTUN()
	dev := NewDevice(tun.TUN(), binds[0], NewLogger(LogLevelSilent, "peer-lifecycle: "))
	t.Cleanup(dev.Close)
	return dev
}

func TestPeerAddRevokeAndExpiry(t *testing.T) {
	activeKey, activeHex := lifecyclePublicKey(t)
	expiredKey, expiredHex := lifecyclePublicKey(t)
	revokedKey, revokedHex := lifecyclePublicKey(t)
	activeIP := netip.MustParseAddr("10.90.0.1")
	expiredIP := netip.MustParseAddr("10.90.0.2")
	revokedIP := netip.MustParseAddr("10.90.0.3")

	dev := lifecycleDevice(t)
	configuration := "replace_peers=true\n" +
		"public_key=" + activeHex + "\nallowed_ip=10.90.0.1/32\n" +
		"public_key=" + expiredHex + "\nallowed_ip=10.90.0.2/32\n" +
		"public_key=" + revokedHex + "\nallowed_ip=10.90.0.3/32\n"
	if err := dev.IpcSet(configuration); err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		key NoisePublicKey
		ip  netip.Addr
	}{
		{key: activeKey, ip: activeIP},
		{key: expiredKey, ip: expiredIP},
		{key: revokedKey, ip: revokedIP},
	} {
		peer := dev.LookupPeer(test.key)
		if peer == nil {
			t.Fatalf("peer %x was not added", test.key[:4])
		}
		if got := dev.allowedips.Lookup(test.ip.AsSlice()); got != peer {
			t.Fatalf("AllowedIP %s is not routed to its peer", test.ip)
		}
	}

	// uservawg-expiry.timer revokes peers whose deadline has passed. The timer
	// remains a platform responsibility; this exercises the core removal path.
	deadlines := map[NoisePublicKey]time.Time{
		activeKey:  time.Now().Add(time.Hour),
		expiredKey: time.Now().Add(-time.Minute),
	}
	now := time.Now()
	for key, deadline := range deadlines {
		if deadline.After(now) {
			continue
		}
		dev.RemovePeer(key)
	}
	if err := dev.IpcSet("public_key=" + revokedHex + "\nremove=true\n"); err != nil {
		t.Fatal(err)
	}

	if peer := dev.LookupPeer(activeKey); peer == nil {
		t.Fatal("unexpired peer was removed")
	}
	if got := dev.allowedips.Lookup(activeIP.AsSlice()); got == nil {
		t.Fatal("unexpired peer lost its AllowedIP")
	}
	for _, test := range []struct {
		name string
		key  NoisePublicKey
		ip   netip.Addr
	}{
		{name: "expired", key: expiredKey, ip: expiredIP},
		{name: "revoked", key: revokedKey, ip: revokedIP},
	} {
		if dev.LookupPeer(test.key) != nil {
			t.Errorf("%s peer is still present", test.name)
		}
		if got := dev.allowedips.Lookup(test.ip.AsSlice()); got != nil {
			t.Errorf("%s peer still owns AllowedIP %s", test.name, test.ip)
		}
	}
}
