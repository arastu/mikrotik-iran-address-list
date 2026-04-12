# MikroTik Iran Address List

This repository builds an "ultimate" Iran IP list for MikroTik routers by merging multiple country-IP sources, deduplicating them, re-aggregating them, and exporting import-ready MikroTik scripts.

## Sources

The generator currently merges these sources:

1. Loyalsoldier `geoip.dat`
   https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat
2. Chocolate4U `geoip.dat`
   https://github.com/Chocolate4U/Iran-v2ray-rules/releases/latest/download/geoip.dat
3. IPDeny aggregated Iran CIDRs
   https://www.ipdeny.com/ipblocks/data/aggregated/ir-aggregated.zone
4. IPDeny Iran country CIDRs
   https://www.ipdeny.com/ipblocks/data/countries/ir.zone
5. IPToASN IPv4 country ranges
   https://iptoasn.com/data/ip2country-v4.tsv.gz
6. IPToASN IPv6 country ranges
   https://iptoasn.com/data/ip2country-v6.tsv.gz

## Output

Running the generator writes these files into `dist/`:

- `iran-ips.rsc`
  Import-ready MikroTik script with deduplicated IPv4 and IPv6 address-list entries.
- `iran-ips-reset-and-import.rsc`
  Same as above, but first removes existing `iran-ips` entries from both IPv4 and IPv6 firewall address-lists.
- `iran-ips.txt`
  Plain CIDR list for inspection or reuse.
- `metadata.json`
  Generation timestamp, source stats, success/failure details, and final IPv4/IPv6 counts.

## Local Usage

```bash
go run ./cmd/iran-ips-gen
```

## Import On MikroTik

If you want a clean replace, import `dist/iran-ips-reset-and-import.rsc`.

If you only want to add new entries, import `dist/iran-ips.rsc`.

Example:

```routeros
/import file-name=iran-ips-reset-and-import.rsc
```
