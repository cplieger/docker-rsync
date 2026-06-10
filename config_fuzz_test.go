package main

import (
	"testing"

	"pgregory.net/rapid"
)

// FuzzParseConfig asserts that parsing arbitrary bytes as YAML config
// never panics. A malformed document must return an error, not crash.
func FuzzParseConfig(f *testing.F) {
	f.Add([]byte("jobs: []"))
	f.Add([]byte("jobs:\n  - name: a\n    local: /a\n"))
	f.Add([]byte("not yaml at all: ["))
	f.Add([]byte(""))
	f.Add([]byte("- - -"))
	f.Add([]byte("jobs:\n  - {}"))
	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = parseConfig(data)
	})
}

// FuzzHasShellMeta asserts the metacharacter check never panics and is
// total over arbitrary input.
func FuzzHasShellMeta(f *testing.F) {
	f.Add("/sources/caddy")
	f.Add("root@host")
	f.Add("a;b")
	f.Add("**/*.lock")
	f.Add("")
	f.Fuzz(func(_ *testing.T, s string) {
		_ = hasShellMeta(s)
	})
}

// TestProperty_ParseConfigNeverPanics feeds random byte slices to the
// parser and confirms it always returns (no panic) regardless of input.
func TestProperty_ParseConfigNeverPanics(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		data := rapid.SliceOf(rapid.Byte()).Draw(rt, "data")
		_, _ = parseConfig(data)
	})
}

// TestProperty_HasShellMetaTotal confirms hasShellMeta is total over
// arbitrary strings and that any string containing a known injection
// character is rejected.
func TestProperty_HasShellMetaTotal(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		s := rapid.String().Draw(rt, "s")
		got := hasShellMeta(s)

		wantMeta := false
		for _, r := range s {
			if r < 0x20 || r == 0x7f {
				wantMeta = true
				break
			}
			for _, m := range shellMetaChars {
				if r == m {
					wantMeta = true
					break
				}
			}
			if wantMeta {
				break
			}
		}
		if got != wantMeta {
			rt.Fatalf("hasShellMeta(%q) = %v, want %v", s, got, wantMeta)
		}
	})
}
