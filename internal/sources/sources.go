package sources

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"net/netip"
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
