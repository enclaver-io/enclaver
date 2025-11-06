// Command server runs inside an Enclaver enclave. It acquires an X.509-SVID
// from the SPIFFE Workload API and serves HTTPS to clients that present an SVID
// of their own, authorizing them by SPIFFE ID rather than by network location.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"

	"github.com/enclaver-io/enclaver/examples/spiffe/internal/spiffesource"
)

// The address the app listens on inside the enclave. Enclaver's ingress proxy
// forwards connections from the host to this port over vsock, so it has to
// match the ingress listen_port in enclaver.yaml.
const defaultListenAddr = "0.0.0.0:8443"

type helloResponse struct {
	Message  string `json:"message"`
	ServerID string `json:"server_id"`
	ClientID string `json:"client_id"`
}

func main() {
	log.SetFlags(log.Ltime)

	if err := run(); err != nil {
		log.Fatalf("server: %v", err)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

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

	authorizer, err := clientAuthorizer(svid.ID.TrustDomain())
	if err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/hello", handleHello(source))

	// MTLSServerConfig presents our SVID, verifies the client's SVID against the
	// trust bundle, and then applies the authorizer to the client's SPIFFE ID.
	server := &http.Server{
		Addr:              envOr("LISTEN_ADDR", defaultListenAddr),
		Handler:           mux,
		TLSConfig:         tlsconfig.MTLSServerConfig(source, source, authorizer),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	log.Printf("serving mTLS on %s", server.Addr)

	// The certificate and key come from the TLS config, so there are no files to
	// name here.
	if err := server.ListenAndServeTLS("", ""); !errors.Is(err, http.ErrServerClosed) {
		return err
	}

	return nil
}

// clientAuthorizer decides which peers are allowed to talk to us. By default
// any workload holding an SVID from our own trust domain is accepted; setting
// AUTHORIZED_CLIENT_ID narrows that to a single SPIFFE ID.
func clientAuthorizer(td spiffeid.TrustDomain) (tlsconfig.Authorizer, error) {
	allowed := os.Getenv("AUTHORIZED_CLIENT_ID")
	if allowed == "" {
		log.Printf("authorizing any client in trust domain %s", td)
		return tlsconfig.AuthorizeMemberOf(td), nil
	}

	id, err := spiffeid.FromString(allowed)
	if err != nil {
		return nil, err
	}

	log.Printf("authorizing client %s", id)
	return tlsconfig.AuthorizeID(id), nil
}

func handleHello(source *workloadapi.X509Source) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// The handshake already rejected anyone without an authorized SVID; this
		// just reports who the caller turned out to be.
		clientID, err := peerID(r)
		if err != nil {
			log.Printf("could not read the client SPIFFE ID: %v", err)
			http.Error(w, "client SPIFFE ID unavailable", http.StatusForbidden)
			return
		}

		var serverID spiffeid.ID
		if svid, err := source.GetX509SVID(); err == nil {
			serverID = svid.ID
		}

		log.Printf("request from %s", clientID)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(helloResponse{
			Message:  "hello from an Enclaver enclave",
			ServerID: serverID.String(),
			ClientID: clientID.String(),
		})
	}
}

func peerID(r *http.Request) (spiffeid.ID, error) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return spiffeid.ID{}, errors.New("no client certificate on the connection")
	}
	return x509svid.IDFromCert(r.TLS.PeerCertificates[0])
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}
