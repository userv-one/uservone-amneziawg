package device

import (
	"fmt"
	"testing"
)

// TestAWGReconfigurationPingPong is the regression test for stale transport
// padding offsets: each UAPI update changes S4 while a TUN reader may already
// be blocked in Read with the previous offset.
func TestAWGReconfigurationPingPong(t *testing.T) {
	goroutineLeakCheck(t)
	pair := genTestPair(t, true,
		"jc", "4", "jmin", "64", "jmax", "128",
		"s1", "16", "s2", "16", "s3", "16", "s4", "16",
		"h1", "1001-1999", "h2", "2001-2999", "h3", "3001-3999", "h4", "4001-4999",
	)

	for index, padding := range []int{0, 24, 8, 40, 16, 32} {
		t.Run(fmt.Sprintf("update_%d_s4_%d", index, padding), func(t *testing.T) {
			update := fmt.Sprintf("s4=%d\ni1=<b 0x%02x>\n", padding, padding)
			for i := range pair {
				if err := pair[i].dev.IpcSet(update); err != nil {
					t.Fatalf("device %d rejected S4 update: %v", i, err)
				}
			}
			pair.Send(t, Ping, nil)
			pair.Send(t, Pong, nil)
		})
	}
}
