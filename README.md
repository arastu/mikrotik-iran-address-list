# MikroTik Iran Address List

This repository builds an "ultimate" Iran IP list for MikroTik routers by merging multiple country-IP sources, deduplicating them, re-aggregating them, and exporting import-ready MikroTik scripts.

The generated address-list name is always `iran-ips`.

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

On 2026-04-12, I verified that Loyalsoldier's `latest` download resolves successfully, and Chocolate4U's release page exposes a `geoip.dat` asset in the latest release.

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

## GitHub Actions

The workflow runs:

- every week
- on manual dispatch

It regenerates the list, updates `dist/`, and commits changes back to the repository automatically.

## Why This Is Better Than A Single Source

No single feed is complete all the time. Some are more aggressive, some lag behind, some have better IPv4 coverage, some have better IPv6 coverage, and some package their data differently.

This project treats each feed as one input, not the truth. The final list is the union of all successful sources, with duplicates and overlaps removed before export.
