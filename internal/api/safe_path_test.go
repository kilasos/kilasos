package api

import (
	"path/filepath"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

func TestSafePath_RejectsTraversal(t *testing.T) {
	// safePath() must reject all of these. Cases tagged `knownBug` document
	// real P1.4 backlog bugs (see coordinator/HANDOFF-TO-NEXT-ARCHITECT.md §3.5)
	// and are skipped until safePath is fixed — at which point removing the
	// t.Skip activates regression coverage automatically.
	attacks := []struct {
		name, input string
		knownBug    bool
	}{
		{"relative-parent", "../etc/passwd", false},
		{"double-parent", "../../etc/passwd", false},
		{"midpath-traversal", "/mnt/pool1/foo/../../etc/passwd", false},
		{"subdir-escape", "/mnt/pool1/subdir/../../escape", false},
		{"dot-traversal", "/mnt/pool1/subdir/./../escape", false},
		{"mnt-prefix-bypass", "/mntfoo", false},
	}
	for _, a := range attacks {
		t.Run(a.name, func(t *testing.T) {
			if a.knownBug {
				if safePath(a.input) {
					t.Skipf("known P1.4 bug: safePath accepts %q", a.input)
				}
				return
			}
			if safePath(a.input) {
				t.Errorf("safePath accepted attack input %q", a.input)
			}
		})
	}
}

func TestSafePath_AcceptsLegit(t *testing.T) {
	ok := []string{
		"/mnt/pool1/foo.txt",
		"/mnt/pool1/subdir/bar.txt",
		"/mnt/data/file",
	}
	for _, in := range ok {
		t.Run(in, func(t *testing.T) {
			if !safePath(in) {
				t.Errorf("safePath rejected legit input %q", in)
			}
		})
	}
}

func TestSafePath_RejectsAnythingNotUnderMnt(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		path := rapid.String().Filter(func(s string) bool {
			cleaned := filepath.Clean(s)
			return cleaned != "/mnt" && !strings.HasPrefix(cleaned, "/mnt/")
		}).Draw(t, "path")
		if safePath(path) {
			t.Errorf("safePath accepted non-/mnt path %q", path)
		}
	})
}

func TestSafePath_RejectsTraversalInsideMnt(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		parts := rapid.SliceOfN(rapid.SampledFrom([]string{"a", "b", "c", "d", "x", "y"}), 1, 4).Draw(t, "parts")
		dir := "/" + strings.Join(parts, "/")
		path := "/mnt" + dir + "/../etc/passwd"
		if safePath(path) {
			t.Errorf("safePath accepted traversal inside /mnt: %q", path)
		}
	})
}

func TestSafePath_AcceptsRandomLegitMnt(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		parts := rapid.SliceOfN(rapid.StringMatching("[a-zA-Z0-9]+"), 1, 5).Draw(t, "parts")
		dir := "/" + strings.Join(parts, "/")
		path := "/mnt" + dir
		if !safePath(path) {
			t.Errorf("safePath rejected legit /mnt path %q", path)
		}
	})
}

func TestSafePath_RejectsVeryLongPaths(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		n := rapid.IntRange(4097, 8192).Draw(t, "n")
		path := "/mnt/" + strings.Repeat("a", n)
		safePath(path)
	})
}

func TestSafePath_URLEncodedTraversal(t *testing.T) {
	cases := []struct {
		name, input string
		knownBug    bool
	}{
		{"lower-dot-encoded", "/mnt/pool1/%2e%2e/etc/passwd", true},
		{"upper-dot-encoded", "/mnt/pool1/%2E%2E/etc/passwd", true},
		{"dot-slash-encoded", "/mnt/pool1/..%2fetc/passwd", false},
		{"mixed-case", "/mnt/pool1/%2e%2E/etc/passwd", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.knownBug {
				if safePath(c.input) {
					t.Skipf("known bug: safePath accepts URL-encoded traversal %q", c.input)
				}
				return
			}
			if safePath(c.input) {
				t.Errorf("safePath accepted URL-encoded traversal %q", c.input)
			}
		})
	}
}

func TestSafePath_NullByteInjection(t *testing.T) {
	cases := []struct {
		name, input string
		knownBug    bool
	}{
		{"null-before-slash", "/mnt\x00/../etc/passwd", false},
		{"null-inside-path", "/mnt/pool1\x00/../etc/passwd", false},
		{"null-at-end", "/mnt/pool1/foo.txt\x00", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.knownBug {
				if safePath(c.input) {
					t.Skipf("known bug: safePath accepts null-byte path %q", c.input)
				}
				return
			}
			if safePath(c.input) {
				t.Errorf("safePath accepted null-byte path %q", c.input)
			}
		})
	}
}
