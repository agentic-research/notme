package verify

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"time"
)

type contextKey string

const identityKey contextKey = "notme-identity"

// Verifier holds the CA trust pool and provides HTTP/gRPC middleware.
type Verifier struct {
	caPool *x509.CertPool
}

// New creates a Verifier from a pre-loaded CA certificate pool.
func New(caPool *x509.CertPool) *Verifier {
	return &Verifier{caPool: caPool}
}

// NewFromPEM creates a Verifier from PEM-encoded CA certificate bytes.
func NewFromPEM(caPEM []byte) (*Verifier, error) {
	pool, err := NewCAPool(caPEM)
	if err != nil {
		return nil, err
	}
	return New(pool), nil
}

// NewFromURL creates a Verifier by fetching the CA cert from a URL.
// Typically: https://auth.notme.bot/.well-known/ca-bundle.pem
func NewFromURL(caURL string) (*Verifier, error) {
	resp, err := http.Get(caURL)
	if err != nil {
		return nil, fmt.Errorf("fetch CA cert: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("fetch CA cert: HTTP %d", resp.StatusCode)
	}

	pem, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}

	return NewFromPEM(pem)
}

// TLSConfig returns a tls.Config that requires and verifies client certs
// against the notme CA. Use this for http.Server or gRPC server.
func (v *Verifier) TLSConfig() *tls.Config {
	return &tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  v.caPool,
	}
}

// RequireMTLS wraps an http.Handler, extracting the verified client cert
// identity into the request context. Returns 401 if no valid cert.
//
// Usage:
//
//	mux.Handle("/api/", verifier.RequireMTLS(handler))
func (v *Verifier) RequireMTLS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, `{"error":"client certificate required"}`, http.StatusUnauthorized)
			return
		}

		cert := r.TLS.PeerCertificates[0]
		identity, err := VerifyClientCert(cert, v.caPool)
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"cert verification failed: %s"}`, err.Error()), http.StatusUnauthorized)
			return
		}

		// Check expiry (TLS library checks this too, but defense-in-depth)
		if identity.ExpiresAt.Before(time.Now()) {
			http.Error(w, `{"error":"certificate expired"}`, http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), identityKey, identity)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// IdentityFromContext extracts the verified Identity from the request context.
// Returns nil if no identity is present (handler not behind RequireMTLS).
func IdentityFromContext(ctx context.Context) *Identity {
	id, _ := ctx.Value(identityKey).(*Identity)
	return id
}
