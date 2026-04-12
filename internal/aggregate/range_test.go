package aggregate

import (
	"net/netip"
	"testing"
)

func TestRangeToPrefixes(t *testing.T) {
	start := netip.MustParseAddr("10.0.0.0")
	end := netip.MustParseAddr("10.0.1.255")

	got, err := RangeToPrefixes(start, end)
	if err != nil {
		t.Fatalf("RangeToPrefixes returned error: %v", err)
	}

	want := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/23"),
	}

	if len(got) != len(want) {
		t.Fatalf("unexpected prefix count: got %d want %d", len(got), len(want))
	}

	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("unexpected prefix at %d: got %s want %s", i, got[i], want[i])
		}
	}
}
