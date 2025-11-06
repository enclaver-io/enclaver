// Package spiffesource connects to the SPIFFE Workload API that Enclaver's
// in-enclave supervisor (odyn) serves, and hands back the X.509-SVID and trust
// bundle that the client and server apps authenticate with.
package spiffesource

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// odyn answers FetchX509SVID with a single response and then closes the stream,
// instead of holding it open and pushing a new SVID as the old one rotates.
// go-spiffe treats the closed stream as a failure and reconnects, and since it
// resets its backoff after every message it receives, the default policy would
// reconnect about once a second and make the SPIRE server mint a fresh SVID
// just as often. Reconnecting on a fixed interval turns those retries into a
// sane refresh loop; drop this once odyn keeps the stream open.
const refreshInterval = 5 * time.Minute

type fixedBackoff struct {
	interval time.Duration
}

func (b fixedBackoff) NewBackoff() workloadapi.Backoff { return b }
func (b fixedBackoff) Next() time.Duration             { return b.interval }
func (b fixedBackoff) Reset()                          {}

// New dials the Workload API and returns a source of both this workload's SVID
// and the trust bundle used to verify its peers. The endpoint address comes
// from SPIFFE_ENDPOINT_SOCKET, which odyn sets to tcp://127.0.0.1:5000 before
// it starts the application.
func New(ctx context.Context) (*workloadapi.X509Source, error) {
	addr, ok := workloadapi.GetDefaultAddress()
	if !ok {
		return nil, fmt.Errorf("%s is not set; is this running under Enclaver with spire configured in enclaver.yaml?", workloadapi.SocketEnv)
	}
	log.Printf("connecting to the SPIFFE Workload API at %s", addr)

	source, err := workloadapi.NewX509Source(ctx,
		workloadapi.WithClientOptions(
			workloadapi.WithBackoffStrategy(fixedBackoff{interval: refreshInterval}),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("connecting to the SPIFFE Workload API: %w", err)
	}

	return source, nil
}
