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
7. plitw ros-country-ips IPv4 (built from the RIPE NCC delegated database)
   https://plitw.github.io/ros-country-ips/routeros_lists/ir_ipv4.rsc
8. plitw ros-country-ips IPv6 (built from the RIPE NCC delegated database)
   https://plitw.github.io/ros-country-ips/routeros_lists/ir_ipv6.rsc
9. MrT3acher MikroTik address-list gist
   https://gist.github.com/MrT3acher/e963287d408cb17fbb0b2342155acaf7
10. Ramtiiin iran-ip
    https://github.com/Ramtiiin/iran-ip
11. RIPEstat country resource list for IR (the upstream feed behind
    https://github.com/MrAriaNet/Get-IP-Iran)
    https://stat.ripe.net/data/country-resource-list/data.json?resource=IR&v4_format=prefix

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

## Auto-Import On MikroTik (Scheduled)

To keep the list fresh automatically, add a script that downloads the latest
`iran-ips-reset-and-import.rsc` and imports it, plus a weekly scheduler.
Tested on RouterOS 7.23.

Because the artifact starts by **removing the whole `iran-ips` list**, a
truncated download or an HTML error page must never reach `/import`. The
script guards this with a size gate (the artifact is ~116 KB; anything under
80 KB aborts and leaves the list untouched).

Paste both blocks into a terminal:

```routeros
/system script add name=iran-ips-update policy=read,write,test,ftp source="
    :local url \"https://raw.githubusercontent.com/arastu/mikrotik-iran-address-list/main/dist/iran-ips-reset-and-import.rsc\"
    :do {
      /tool fetch url=\$url dst-path=iran-ips-latest.rsc
    } on-error={
      :log error \"iran-ips update: fetch failed - list unchanged\"
      :error \"fetch failed\"
    }
    :delay 2s
    :local sz 0
    :do { :set sz [/file get iran-ips-latest.rsc size] } on-error={}
    :if (\$sz < 80000) do={
      :log error (\"iran-ips update aborted: downloaded file too small (\" . \$sz . \" bytes) - list unchanged\")
      :error \"file too small\"
    }
    /import iran-ips-latest.rsc
    :log info (\"iran-ips refreshed: \" . [:len [/ip firewall address-list find list=iran-ips]] . \" IPv4 + \" . [:len [/ipv6 firewall address-list find list=iran-ips]] . \" IPv6 entries\")
"
```

```routeros
/system scheduler add name=iran-ips-update interval=7d start-date=2026-08-09 start-time=06:30:00 \
    on-event="/system script run iran-ips-update" policy=read,write,test,ftp \
    comment="weekly iran-ips refresh"
```

Notes:

- Set `start-date` to any Sunday. The GitHub Actions rebuild runs Sundays at
  02:17 UTC, so schedule the import a few hours later (06:30 Tehran time in
  the example) to pick up the fresh build.
- The router must be able to reach `raw.githubusercontent.com`
  (Fastly, `185.199.108.0/22`). From networks where GitHub is throttled or
  blocked, route that prefix through a VPN/tunnel first.
- Check the result anytime with
  `:put [:len [/ip firewall address-list find list=iran-ips]]`.
- Entries added to `iran-ips` by hand on the router will be wiped on the next
  scheduled import. Add permanent extras to the generator sources instead.

## GitHub Actions

The workflow runs:

- every week
- on manual dispatch

It regenerates the list, updates `dist/`, and commits changes back to the repository automatically.

## Why This Is Better Than A Single Source

No single feed is complete all the time. Some are more aggressive, some lag behind, some have better IPv4 coverage, some have better IPv6 coverage, and some package their data differently.

This project treats each feed as one input, not the truth. The final list is the union of all successful sources, with duplicates and overlaps removed before export.
