package sources

import (
	"net/netip"
	"testing"
)

func TestParseRouterOSRsc(t *testing.T) {
	body := []byte(`# IR ipv4 Address List for RouterOS
# Generated at 2026-06-05 08:10:57

/ip firewall address-list
remove [find comment="ir_ipv4"]

add list="ir_ipv4" address=2.57.3.0/24 comment="ir_ipv4"
/ip firewall address-list add address=94.24.16.0/21 list=iran
add address=2.144.0.0/14 list=IRAN
add address=94.184.96.0/19 comment=banksepah.ir list=IRAN
add address=10.3.77.116 comment=banksepah.ir list=IRAN
:do { add address=5.160.0.0/16 list=NoNAT} on-error={}
:do { add address=10.0.0.0/8 list=NoNAT} on-error={}
add list="ir_ipv6" address=2001:790::/32 comment="ir_ipv6"
add address=130.244.71.74/32 list=iran
`)

	prefixes, err := parseRouterOSRsc(body)
	if err != nil {
		t.Fatalf("parseRouterOSRsc: %v", err)
	}

	want := []netip.Prefix{
		netip.MustParsePrefix("2.57.3.0/24"),
		netip.MustParsePrefix("94.24.16.0/21"),
		netip.MustParsePrefix("2.144.0.0/14"),
		netip.MustParsePrefix("94.184.96.0/19"),
		netip.MustParsePrefix("5.160.0.0/16"),
		netip.MustParsePrefix("2001:790::/32"),
		netip.MustParsePrefix("130.244.71.74/32"),
	}

	if len(prefixes) != len(want) {
		t.Fatalf("got %d prefixes, want %d: %v", len(prefixes), len(want), prefixes)
	}
	for i, prefix := range want {
		if prefixes[i] != prefix {
			t.Errorf("prefix %d: got %s, want %s", i, prefixes[i], prefix)
		}
	}
}

func TestParseRouterOSRscSkipsPrivate(t *testing.T) {
	body := []byte(`add address=10.0.0.0/8 list=NoNAT
add address=192.168.1.0/24 list=test
add address=172.16.0.0/12 list=test
`)

	if _, err := parseRouterOSRsc(body); err == nil {
		t.Fatal("expected error when only private entries are present")
	}
}

func TestParseRouterOSRscEmpty(t *testing.T) {
	if _, err := parseRouterOSRsc([]byte("# nothing here\n")); err == nil {
		t.Fatal("expected error for script without address entries")
	}
}

func TestParseRIPEStat(t *testing.T) {
	body := []byte(`{
		"data": {
			"resources": {
				"ipv4": ["2.144.0.0/14", "5.22.0.0/17", "31.2.128.0 - 31.2.255.255"],
				"ipv6": ["2001:790::/32"]
			}
		}
	}`)

	prefixes, err := parseRIPEStat(body)
	if err != nil {
		t.Fatalf("parseRIPEStat: %v", err)
	}

	want := map[netip.Prefix]bool{
		netip.MustParsePrefix("2.144.0.0/14"):  true,
		netip.MustParsePrefix("5.22.0.0/17"):   true,
		netip.MustParsePrefix("31.2.128.0/17"): true,
		netip.MustParsePrefix("2001:790::/32"): true,
	}

	if len(prefixes) != len(want) {
		t.Fatalf("got %d prefixes, want %d: %v", len(prefixes), len(want), prefixes)
	}
	for _, prefix := range prefixes {
		if !want[prefix] {
			t.Errorf("unexpected prefix %s", prefix)
		}
	}
}

func TestParseRIPEStatEmpty(t *testing.T) {
	if _, err := parseRIPEStat([]byte(`{"data":{"resources":{"ipv4":[],"ipv6":[]}}}`)); err == nil {
		t.Fatal("expected error for empty resource list")
	}
}
