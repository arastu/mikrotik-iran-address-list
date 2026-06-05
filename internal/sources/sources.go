package sources

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/golang/protobuf/proto"

	"github.com/arastu/mikrotik-iran-address-list/internal/aggregate"
	"github.com/arastu/mikrotik-iran-address-list/internal/fetch"
	"github.com/arastu/mikrotik-iran-address-list/internal/mikrotik"
)

type Source struct {
	Name   string
	URL    string
	Parser func([]byte) ([]netip.Prefix, error)
}

type List []Source

func Default() List {
	return List{
		{
			Name:   "Loyalsoldier geoip.dat",
			URL:    "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat",
			Parser: parseGeoIPDat,
		},
		{
			Name:   "Chocolate4U geoip.dat",
			URL:    "https://github.com/Chocolate4U/Iran-v2ray-rules/releases/latest/download/geoip.dat",
			Parser: parseGeoIPDat,
		},
		{
			Name:   "IPDeny aggregated IR",
			URL:    "https://www.ipdeny.com/ipblocks/data/aggregated/ir-aggregated.zone",
			Parser: parseCIDRLines,
		},
		{
			Name:   "IPDeny country IR",
			URL:    "https://www.ipdeny.com/ipblocks/data/countries/ir.zone",
			Parser: parseCIDRLines,
		},
		{
			Name:   "IPToASN v4 IR",
			URL:    "https://iptoasn.com/data/ip2country-v4.tsv.gz",
			Parser: parseIPToASNGzip("IR"),
		},
		{
			Name:   "IPToASN v6 IR",
			URL:    "https://iptoasn.com/data/ip2country-v6.tsv.gz",
			Parser: parseIPToASNGzip("IR"),
		},
		{
			Name:   "plitw ros-country-ips v4 (RIPE delegated)",
			URL:    "https://plitw.github.io/ros-country-ips/routeros_lists/ir_ipv4.rsc",
			Parser: parseRouterOSRsc,
		},
		{
			Name:   "plitw ros-country-ips v6 (RIPE delegated)",
			URL:    "https://plitw.github.io/ros-country-ips/routeros_lists/ir_ipv6.rsc",
			Parser: parseRouterOSRsc,
		},
		{
			Name:   "MrT3acher MikroTik address list gist",
			URL:    "https://gist.githubusercontent.com/MrT3acher/e963287d408cb17fbb0b2342155acaf7/raw/add-iran-address-list.rsc",
			Parser: parseRouterOSRsc,
		},
		{
			Name:   "Ramtiiin iran-ip",
			URL:    "https://raw.githubusercontent.com/Ramtiiin/iran-ip/main/ip-list.rsc",
			Parser: parseRouterOSRsc,
		},
		{
			Name:   "RIPEstat country resource list IR",
			URL:    "https://stat.ripe.net/data/country-resource-list/data.json?resource=IR&v4_format=prefix",
			Parser: parseRIPEStat,
		},
	}
}

func (l List) Collect(ctx context.Context, fetcher *fetch.Fetcher) ([]netip.Prefix, mikrotik.Report, error) {
	report := mikrotik.Report{
		GeneratedAt: time.Now().UTC(),
		ListName:    "iran-ips",
	}

	type result struct {
		report   *mikrotik.SourceReport
		prefixes []netip.Prefix
		err      error
	}

	results := make(chan result, len(l))
	var wg sync.WaitGroup

	for _, source := range l {
		source := source
		wg.Add(1)
		go func() {
			defer wg.Done()

			body, err := fetcher.Get(ctx, source.Name, source.URL)
			if err != nil {
				results <- result{err: fmt.Errorf("%s: %w", source.Name, err)}
				return
			}

			prefixes, err := source.Parser(body)
			if err != nil {
				results <- result{err: fmt.Errorf("%s: %w", source.Name, err)}
				return
			}

			results <- result{
				report: &mikrotik.SourceReport{
					Name:        source.Name,
					URL:         source.URL,
					PrefixCount: len(prefixes),
				},
				prefixes: prefixes,
			}
		}()
	}

	wg.Wait()
	close(results)

	var all []netip.Prefix
	for item := range results {
		if item.err != nil {
			report.FailedSource = append(report.FailedSource, item.err.Error())
			continue
		}

		report.Sources = append(report.Sources, *item.report)
		all = append(all, item.prefixes...)
	}

	if len(all) == 0 {
		return nil, report, fmt.Errorf("all sources failed")
	}

	sort.Slice(report.Sources, func(i, j int) bool {
		return report.Sources[i].Name < report.Sources[j].Name
	})
	sort.Strings(report.FailedSource)

	merged, err := aggregate.Merge(all)
	if err != nil {
		return nil, report, fmt.Errorf("merge prefixes: %w", err)
	}

	report.SourceCount = len(report.Sources)
	report.PrefixCount = len(merged)
	for _, prefix := range merged {
		if prefix.Addr().Is4() {
			report.IPv4Count++
		} else {
			report.IPv6Count++
		}
	}

	return merged, report, nil
}

func parseCIDRLines(body []byte) ([]netip.Prefix, error) {
	lines := strings.Split(string(body), "\n")
	prefixes := make([]netip.Prefix, 0, len(lines))

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		prefix, err := netip.ParsePrefix(line)
		if err != nil {
			return nil, fmt.Errorf("parse CIDR %q: %w", line, err)
		}
		prefixes = append(prefixes, prefix.Masked())
	}

	return prefixes, nil
}

var routerOSAddressPattern = regexp.MustCompile(`(?:^|\s)address=("?)([0-9A-Fa-f:.\/]+)("?)(?:\s|$)`)

// parseRouterOSRsc extracts address= values from MikroTik RouterOS script
// lines such as:
//
//	add list="ir_ipv4" address=2.57.3.0/24 comment="ir_ipv4"
//	/ip firewall address-list add address=94.24.16.0/21 list=iran
//	add address=2.144.0.0/14 list=IRAN
//
// Bare addresses without a prefix length are treated as host routes.
// Private and otherwise non-public entries are skipped because some
// community-maintained lists mix RFC1918 helpers into their scripts.
func parseRouterOSRsc(body []byte) ([]netip.Prefix, error) {
	var prefixes []netip.Prefix
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		match := routerOSAddressPattern.FindStringSubmatch(line)
		if match == nil {
			continue
		}

		value := match[2]
		var prefix netip.Prefix
		if strings.Contains(value, "/") {
			parsed, err := netip.ParsePrefix(value)
			if err != nil {
				return nil, fmt.Errorf("parse address %q: %w", value, err)
			}
			prefix = parsed.Masked()
		} else {
			addr, err := netip.ParseAddr(value)
			if err != nil {
				return nil, fmt.Errorf("parse address %q: %w", value, err)
			}
			prefix = netip.PrefixFrom(addr, addr.BitLen())
		}

		if !isPublicPrefix(prefix) {
			continue
		}
		prefixes = append(prefixes, prefix)
	}

	if len(prefixes) == 0 {
		return nil, fmt.Errorf("no address entries found in RouterOS script")
	}

	return prefixes, nil
}

// parseRIPEStat reads the RIPEstat country-resource-list response, the
// upstream feed behind MrAriaNet/Get-IP-Iran. Entries are CIDR prefixes
// when v4_format=prefix is requested, but ranges like "a.b.c.d-e.f.g.h"
// are handled too in case the format parameter is ever dropped.
func parseRIPEStat(body []byte) ([]netip.Prefix, error) {
	var response struct {
		Data struct {
			Resources struct {
				IPv4 []string `json:"ipv4"`
				IPv6 []string `json:"ipv6"`
			} `json:"resources"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("unmarshal RIPEstat response: %w", err)
	}

	entries := append(response.Data.Resources.IPv4, response.Data.Resources.IPv6...)
	if len(entries) == 0 {
		return nil, fmt.Errorf("no IR resources found in RIPEstat response")
	}

	var prefixes []netip.Prefix
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		if start, end, ok := strings.Cut(entry, "-"); ok {
			startAddr, err := netip.ParseAddr(strings.TrimSpace(start))
			if err != nil {
				return nil, fmt.Errorf("parse range start %q: %w", entry, err)
			}
			endAddr, err := netip.ParseAddr(strings.TrimSpace(end))
			if err != nil {
				return nil, fmt.Errorf("parse range end %q: %w", entry, err)
			}
			rangePrefixes, err := aggregate.RangeToPrefixes(startAddr, endAddr)
			if err != nil {
				return nil, err
			}
			prefixes = append(prefixes, rangePrefixes...)
			continue
		}

		prefix, err := netip.ParsePrefix(entry)
		if err != nil {
			return nil, fmt.Errorf("parse resource %q: %w", entry, err)
		}
		prefixes = append(prefixes, prefix.Masked())
	}

	return prefixes, nil
}

// isPublicPrefix reports whether the prefix is publicly routable address
// space: global unicast and not RFC1918 / ULA private space.
func isPublicPrefix(prefix netip.Prefix) bool {
	addr := prefix.Addr()
	return addr.IsGlobalUnicast() && !addr.IsPrivate()
}

func parseIPToASNGzip(countryCode string) func([]byte) ([]netip.Prefix, error) {
	return func(body []byte) ([]netip.Prefix, error) {
		reader, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, fmt.Errorf("open gzip: %w", err)
		}
		defer reader.Close()

		decompressed, err := ioReadAll(reader)
		if err != nil {
			return nil, fmt.Errorf("read gzip: %w", err)
		}

		var prefixes []netip.Prefix
		for _, line := range strings.Split(string(decompressed), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}

			parts := strings.Split(line, "\t")
			if len(parts) < 3 || parts[2] != countryCode {
				continue
			}

			start, err := netip.ParseAddr(parts[0])
			if err != nil {
				return nil, fmt.Errorf("parse start IP %q: %w", parts[0], err)
			}

			end, err := netip.ParseAddr(parts[1])
			if err != nil {
				return nil, fmt.Errorf("parse end IP %q: %w", parts[1], err)
			}

			rangePrefixes, err := aggregate.RangeToPrefixes(start, end)
			if err != nil {
				return nil, err
			}
			prefixes = append(prefixes, rangePrefixes...)
		}

		return prefixes, nil
	}
}

func parseGeoIPDat(body []byte) ([]netip.Prefix, error) {
	var list geoIPList
	if err := proto.Unmarshal(body, &list); err != nil {
		return nil, fmt.Errorf("unmarshal geoip.dat: %w", err)
	}

	var prefixes []netip.Prefix
	for _, entry := range list.Entry {
		if entry == nil {
			continue
		}

		code := strings.ToUpper(strings.TrimSpace(entry.CountryCode))
		if code == "" {
			code = strings.ToUpper(strings.TrimSpace(entry.Code))
		}
		if code != "IR" {
			continue
		}

		for _, cidr := range entry.CIDR {
			if cidr == nil {
				continue
			}

			addr, ok := netip.AddrFromSlice(cidr.IP)
			if !ok {
				return nil, fmt.Errorf("invalid IP bytes in geoip.dat")
			}

			prefix := netip.PrefixFrom(addr.Unmap(), int(cidr.Prefix)).Masked()
			prefixes = append(prefixes, prefix)
		}
	}

	if len(prefixes) == 0 {
		return nil, fmt.Errorf("no IR entry found in geoip.dat")
	}

	return prefixes, nil
}

func ioReadAll(r *gzip.Reader) ([]byte, error) {
	var b bytes.Buffer
	if _, err := b.ReadFrom(r); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

type geoIPList struct {
	Entry []*geoIP `protobuf:"bytes,1,rep,name=entry,proto3" json:"entry,omitempty"`
}

func (*geoIPList) Reset()         {}
func (*geoIPList) String() string { return "geoIPList" }
func (*geoIPList) ProtoMessage()  {}

type geoIP struct {
	CountryCode string  `protobuf:"bytes,1,opt,name=country_code,json=countryCode,proto3" json:"country_code,omitempty"`
	CIDR        []*cidr `protobuf:"bytes,2,rep,name=cidr,proto3" json:"cidr,omitempty"`
	Inverse     bool    `protobuf:"varint,3,opt,name=inverse_match,json=inverseMatch,proto3" json:"inverse_match,omitempty"`
	Resource    string  `protobuf:"bytes,4,opt,name=resource_hash,json=resourceHash,proto3" json:"resource_hash,omitempty"`
	Code        string  `protobuf:"bytes,5,opt,name=code,proto3" json:"code,omitempty"`
}

func (*geoIP) Reset()         {}
func (*geoIP) String() string { return "geoIP" }
func (*geoIP) ProtoMessage()  {}

type cidr struct {
	IP     []byte `protobuf:"bytes,1,opt,name=ip,proto3" json:"ip,omitempty"`
	Prefix uint32 `protobuf:"varint,2,opt,name=prefix,proto3" json:"prefix,omitempty"`
}

func (*cidr) Reset()         {}
func (*cidr) String() string { return "cidr" }
func (*cidr) ProtoMessage()  {}
