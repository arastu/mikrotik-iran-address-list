package main

import (
	"context"
	"flag"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/arastu/mikrotik-iran-address-list/internal/fetch"
	"github.com/arastu/mikrotik-iran-address-list/internal/mikrotik"
	"github.com/arastu/mikrotik-iran-address-list/internal/sources"
)

func main() {
	var (
		outDir   = flag.String("out-dir", "dist", "directory to write generated files into")
		listName = flag.String("list-name", "iran-ips", "MikroTik address-list name")
		timeout  = flag.Duration("timeout", 60*time.Second, "per-request timeout")
	)
	flag.Parse()

	ctx := context.Background()

	fetcher, err := fetch.NewFetcher(fetch.Config{
		Timeout: *timeout,
	})
	if err != nil {
		log.Fatalf("create fetcher: %v", err)
	}

	sourceList := sources.Default()
	prefixes, report, err := sourceList.Collect(ctx, fetcher)
	if err != nil {
		log.Fatalf("collect sources: %v", err)
	}
	report.ListName = *listName

	sort.Slice(prefixes, func(i, j int) bool {
		return comparePrefix(prefixes[i], prefixes[j]) < 0
	})

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		log.Fatalf("create output directory: %v", err)
	}

	rscPath := filepath.Join(*outDir, "iran-ips.rsc")
	resetPath := filepath.Join(*outDir, "iran-ips-reset-and-import.rsc")
	txtPath := filepath.Join(*outDir, "iran-ips.txt")
	metaPath := filepath.Join(*outDir, "metadata.json")

	if err := mikrotik.WriteScript(rscPath, *listName, prefixes, report.GeneratedAt, false); err != nil {
		log.Fatalf("write %s: %v", rscPath, err)
	}

	if err := mikrotik.WriteScript(resetPath, *listName, prefixes, report.GeneratedAt, true); err != nil {
		log.Fatalf("write %s: %v", resetPath, err)
	}

	if err := mikrotik.WritePlainList(txtPath, prefixes); err != nil {
		log.Fatalf("write %s: %v", txtPath, err)
	}

	if err := report.WriteJSON(metaPath); err != nil {
		log.Fatalf("write %s: %v", metaPath, err)
	}

	log.Printf("generated %d unique prefixes from %d sources into %s", len(prefixes), len(report.Sources), *outDir)
}

func comparePrefix(a, b netip.Prefix) int {
	if a.Addr().BitLen() != b.Addr().BitLen() {
		return a.Addr().BitLen() - b.Addr().BitLen()
	}
	if a.Addr().Less(b.Addr()) {
		return -1
	}
	if b.Addr().Less(a.Addr()) {
		return 1
	}
	return a.Bits() - b.Bits()
}
