// Command client runs inside an Enclaver enclave. It acquires an X.509-SVID
// from the SPIFFE Workload API and calls the server app over mTLS, presenting
// its SVID and requiring the server to present an expected one.
package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"

	"github.com/enclaver-io/enclaver/examples/spiffe/internal/spiffesource"
)

const (
	// "host" is Enclaver's name for the machine outside the enclave. The
	// connection leaves through the enclave egress proxy, which is why "host"
	// has to appear in the egress allow list in enclaver.yaml.
	defaultServerURL = "https://host:8443/hello"
	defaultServerID  = "spiffe://example.org/workload/server"
	defaultInterval  = 5 * time.Second
)

func main() {
	log.SetFlags(log.Ltime)

	if err := run(); err != nil {
		log.Fatalf("client: %v", err)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	serverURL := envOr("SERVER_URL", defaultServerURL)

	serverID, err := spiffeid.FromString(envOr("SERVER_SPIFFE_ID", defaultServerID))
	if err != nil {
		return fmt.Errorf("parsing SERVER_SPIFFE_ID: %w", err)
	}

	interval, err := time.ParseDuration(envOr("REQUEST_INTERVAL", defaultInterval.String()))
	if err != nil {
		return fmt.Errorf("parsing REQUEST_INTERVAL: %w", err)
	}

	source, err := spiffesource.New(ctx)
	if err != nil {
		return err
	}
	defer source.Close()

	svid, err := source.GetX509SVID()
	if err != nil {
		return err
	}
	log.Printf("acquired X.509-SVID for %s", svid.ID)

	// MTLSClientConfig presents our SVID and authorizes the server by its SPIFFE
	// ID instead of by hostname, so the DNS name we dialed does not have to
	// match anything in the server's certificate.
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			// odyn points https_proxy at the in-enclave egress proxy.
			Proxy:           http.ProxyFromEnvironment,
			TLSClientConfig: tlsconfig.MTLSClientConfig(source, source, tlsconfig.AuthorizeID(serverID)),
		},
	}

	log.Printf("calling %s, expecting to reach %s", serverURL, serverID)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		if err := call(ctx, client, serverURL); err != nil {
			log.Printf("request failed: %v", err)
		}

		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func call(ctx context.Context, client *http.Client, url string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %s", resp.Status, body)
	}

	log.Printf("response: %s", body)
	return nil
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}
