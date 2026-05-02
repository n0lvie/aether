package orchestrator

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/aether-project/aether/internal/crypto"
)

// DoHOracle implements SeedOracle by querying DNS-over-HTTPS providers
// for TXT records containing Aether seed nodes. This helps bypass
// simple DNS blocking and DPI.
type DoHOracle struct {
	client    *http.Client
	domain    string
	endpoints []string
}

// NewDoHOracle creates a new DoH oracle.
func NewDoHOracle(domain string) *DoHOracle {
	return &DoHOracle{
		client: &http.Client{},
		domain: domain,
		endpoints: []string{
			"https://cloudflare-dns.com/dns-query",
			"https://dns.google/resolve",
		},
	}
}

// Name returns the oracle identifier.
func (o *DoHOracle) Name() string {
	return "DNS-over-HTTPS"
}

// dohResponse represents a JSON DNS response.
type dohResponse struct {
	Status int `json:"Status"`
	Answer []struct {
		Name string `json:"name"`
		Type int    `json:"type"`
		Data string `json:"data"`
	} `json:"Answer"`
}

// Discover queries DoH endpoints and parses TXT records for seed nodes.
func (o *DoHOracle) Discover(ctx context.Context) ([]crypto.SeedNode, error) {
	var seeds []crypto.SeedNode
	var lastErr error

	for _, endpoint := range o.endpoints {
		url := fmt.Sprintf("%s?name=%s&type=TXT", endpoint, o.domain)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Accept", "application/dns-json")

		resp, err := o.client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("bad status code: %d", resp.StatusCode)
			continue
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			lastErr = err
			continue
		}

		var dnsResp dohResponse
		if err := json.Unmarshal(body, &dnsResp); err != nil {
			lastErr = err
			continue
		}

		if dnsResp.Status != 0 {
			lastErr = fmt.Errorf("dns response error status: %d", dnsResp.Status)
			continue
		}

		for _, ans := range dnsResp.Answer {
			if ans.Type == 16 { // 16 = TXT
				// Format: "v=aether1 seed=<base64>"
				data := strings.Trim(ans.Data, "\"")
				if strings.HasPrefix(data, "v=aether1 ") {
					parts := strings.Split(data, " ")
					for _, part := range parts {
						if strings.HasPrefix(part, "seed=") {
							b64 := strings.TrimPrefix(part, "seed=")
							seedBytes, err := base64.StdEncoding.DecodeString(b64)
							if err != nil {
								continue
							}

							// Assume IPv4 for simplicity in this oracle
							node, err := crypto.UnmarshalSeedNode(seedBytes, false)
							if err == nil {
								seeds = append(seeds, *node)
							} else {
								// Try IPv6
								node, err = crypto.UnmarshalSeedNode(seedBytes, true)
								if err == nil {
									seeds = append(seeds, *node)
								}
							}
						}
					}
				}
			}
		}

		// If we found seeds from this endpoint, return them (don't query others)
		if len(seeds) > 0 {
			return seeds, nil
		}
	}

	if len(seeds) == 0 && lastErr != nil {
		return nil, lastErr
	}
	return seeds, nil
}
