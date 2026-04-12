package fetch

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

const userAgent = "mikrotik-iran-address-list/1.0 (+https://github.com/arastu/mikrotik-iran-address-list)"

type Config struct {
	Timeout time.Duration
}

type Fetcher struct {
	client *http.Client
}

func NewFetcher(cfg Config) (*Fetcher, error) {
	client := &http.Client{
		Timeout:   cfg.Timeout,
		Transport: baseTransport(),
	}

	return &Fetcher{client: client}, nil
}

func (f *Fetcher) Get(ctx context.Context, sourceName, rawURL string) ([]byte, error) {
	body, err := f.get(ctx, f.client, rawURL)
	if err != nil {
		return nil, fmt.Errorf("%s fetch failed: %w", sourceName, err)
	}
	return body, nil
}

func (f *Fetcher) get(ctx context.Context, client *http.Client, rawURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "*/*")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("unexpected status %s", resp.Status)
	}

	return io.ReadAll(resp.Body)
}

func baseTransport() *http.Transport {
	return &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          50,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   30 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
	}
}
