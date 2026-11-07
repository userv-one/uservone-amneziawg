package device

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func TestObfChainRejectsUnsafeSpecifications(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		spec string
	}{
		{name: "negative random length", spec: "<r -1>"},
		{name: "negative chars length", spec: "<rc -1>"},
		{name: "negative digits length", spec: "<rd -1>"},
		{name: "zero random length", spec: "<r 0>"},
		{name: "negative data size length", spec: "<dz -1>"},
		{name: "zero data size length", spec: "<dz 0>"},
		{name: "oversized data size length", spec: "<dz 9>"},
		{name: "oversized packet", spec: "<r 65508>"},
		{name: "combined oversized packet", spec: "<r 65000><rc 508>"},
		{name: "trailing garbage", spec: "<r 8>garbage"},
		{name: "leading garbage", spec: "garbage<r 8>"},
		{name: "stray closing bracket", spec: "<r 8>>"},
		{name: "extra random argument", spec: "<r 8 extra>"},
		{name: "unexpected timestamp argument", spec: "<t now>"},
		{name: "unexpected data argument", spec: "<d value>"},
		{name: "multiple payload fields", spec: "<d><ds>"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := newObfChain(test.spec); err == nil {
				t.Fatalf("newObfChain(%q) unexpectedly succeeded", test.spec)
			}
		})
	}
}

func TestObfChainAcceptsCompatibleSpecifications(t *testing.T) {
	t.Parallel()

	for _, spec := range []string{
		"<b 0xdead>",
		"<b 0xdead><r 8><rc 4><rd 4><t>",
		"<d>",
		"<ds>",
		"<dz 2><d>",
	} {
		t.Run(strings.ReplaceAll(spec, " ", "_"), func(t *testing.T) {
			t.Parallel()
			if _, err := newObfChain(spec); err != nil {
				t.Fatalf("newObfChain(%q): %v", spec, err)
			}
		})
	}
}

func deobfuscateResult(chain *obfChain, dst, src []byte) (ok bool, panicValue any) {
	defer func() {
		panicValue = recover()
	}()
	ok = chain.Deobfuscate(dst, src)
	return ok, nil
}

func TestObfChainDeobfuscationRejectsTruncatedAndTrailingData(t *testing.T) {
	t.Parallel()

	chain, err := newObfChain("<b 0xdead><r 4><rc 2><rd 2><t>")
	if err != nil {
		t.Fatal(err)
	}
	encoded := make([]byte, chain.ObfuscatedLen(0))
	chain.Obfuscate(encoded, nil)

	for length := 0; length <= len(encoded)+1; length++ {
		t.Run(fmt.Sprintf("length_%d", length), func(t *testing.T) {
			src := make([]byte, length)
			copy(src, encoded)
			dst := make([]byte, max(0, chain.DeobfuscatedLen(length)))
			ok, panicValue := deobfuscateResult(chain, dst, src)
			if panicValue != nil {
				t.Fatalf("Deobfuscate panicked for %d bytes: %v", length, panicValue)
			}
			wantOK := length == len(encoded)
			if ok != wantOK {
				t.Fatalf("Deobfuscate returned %v for %d bytes, want %v", ok, length, wantOK)
			}
		})
	}
}

func TestDataStringObfuscationChecksEncoding(t *testing.T) {
	t.Parallel()

	chain, err := newObfChain("<b 0xdead><ds>")
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("userv.one")
	encoded := make([]byte, chain.ObfuscatedLen(len(payload)))
	chain.Obfuscate(encoded, payload)
	decoded := make([]byte, chain.DeobfuscatedLen(len(encoded)))
	ok, panicValue := deobfuscateResult(chain, decoded, encoded)
	if panicValue != nil {
		t.Fatalf("valid Deobfuscate panicked: %v", panicValue)
	}
	if !ok || !bytes.Equal(decoded, payload) {
		t.Fatalf("round trip failed: ok=%v decoded=%q", ok, decoded)
	}

	encoded[len(encoded)-1] = '*'
	decoded = make([]byte, chain.DeobfuscatedLen(len(encoded)))
	ok, panicValue = deobfuscateResult(chain, decoded, encoded)
	if panicValue != nil {
		t.Fatalf("invalid Deobfuscate panicked: %v", panicValue)
	}
	if ok {
		t.Fatal("invalid base64 payload was accepted")
	}
}

func FuzzObfChainDeobfuscationNeverPanics(f *testing.F) {
	for _, seed := range [][]byte{nil, {}, {0}, []byte("userv.one"), []byte("***"), make([]byte, 65507)} {
		f.Add(seed)
	}
	var chains []*obfChain
	for _, spec := range []string{
		"<b 0xdead><r 4><rc 2><rd 2><t>",
		"<d>",
		"<ds>",
		"<dz 2><d>",
		"<b 0xdead><ds>",
	} {
		chain, err := newObfChain(spec)
		if err != nil {
			f.Fatal(err)
		}
		chains = append(chains, chain)
	}
	f.Fuzz(func(t *testing.T, src []byte) {
		if len(src) > maxObfPacketSize {
			t.Skip()
		}
		for _, chain := range chains {
			dst := make([]byte, max(0, chain.DeobfuscatedLen(len(src))))
			_ = chain.Deobfuscate(dst, src)
		}
	})
}
