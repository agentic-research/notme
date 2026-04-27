// Package verify provides lightweight notme bridge cert verification.
//
// A service needs only this package + the CA cert PEM to verify agent identity.
// No notme Worker, no workerd, no WIMSE library, no external dependencies.
//
// Usage:
//
//	v, _ := verify.NewFromURL("https://auth.notme.bot/.well-known/ca-bundle.pem")
//	mux.Handle("/api/", v.RequireMTLS(handler))
//
//	func handler(w http.ResponseWriter, r *http.Request) {
//	    id := verify.IdentityFromContext(r.Context())
//	    fmt.Println(id.URI)    // wimse://notme.bot/gha/agentic-research/notme
//	    fmt.Println(id.Scopes) // [bridgeCert sign:git]
//	}
package verify

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"strings"
	"time"
)

// Identity represents a verified notme bridge cert identity.
type Identity struct {
	// URI is the WIMSE identity from the cert SAN (e.g. wimse://notme.bot/gha/owner/repo).
	URI string

	// Scopes are the granted capabilities from the cert extensions.
	Scopes []string

	// Subject is the principal UUID or OIDC sub claim from the cert CN.
	Subject string

	// Epoch is the CA epoch at issuance time.
	Epoch int

	// AuthMethod is how the caller authenticated (gha-oidc, passkey, bootstrap).
	AuthMethod string

	// Binding is the hex SHA-256 of both SPKI keys (P-256 || Ed25519).
	Binding string

	// ExpiresAt is the cert expiry.
	ExpiresAt time.Time

	// Raw is the original x509.Certificate for advanced use.
	Raw *x509.Certificate
}

// Custom OID arc for notme extensions (placeholder — replace with real PEN).
var (
	oidSubjectIdentity = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, 1}
	oidIssuanceTime    = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, 2}
	oidScopes          = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, 3}
	oidEpoch           = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, 4}
	oidAuthMethod      = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, 5}
	oidPeerBinding     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, 6}
)

// ParseIdentity extracts a notme Identity from a verified X.509 client certificate.
// The cert MUST already be verified against the CA trust pool — this function
// only parses, it does not validate the signature chain.
func ParseIdentity(cert *x509.Certificate) (*Identity, error) {
	id := &Identity{
		Subject:   cert.Subject.CommonName,
		ExpiresAt: cert.NotAfter,
		Raw:       cert,
	}

	// Extract WIMSE identity from SAN URIs
	for _, uri := range cert.URIs {
		if strings.HasPrefix(uri.String(), "wimse://") {
			id.URI = uri.String()
			break
		}
	}

	// Parse custom extensions
	for _, ext := range cert.Extensions {
		switch {
		case ext.Id.Equal(oidScopes):
			scopes, err := parseScopeSequence(ext.Value)
			if err == nil {
				id.Scopes = scopes
			}
		case ext.Id.Equal(oidEpoch):
			epoch, err := parseInteger(ext.Value)
			if err == nil {
				id.Epoch = epoch
			}
		case ext.Id.Equal(oidAuthMethod):
			s, err := parseUTF8String(ext.Value)
			if err == nil {
				id.AuthMethod = s
			}
		case ext.Id.Equal(oidPeerBinding):
			id.Binding = fmt.Sprintf("%x", ext.Value)
		}
	}

	return id, nil
}

// NewCAPool creates a certificate pool from PEM-encoded CA certificate(s).
func NewCAPool(caPEM []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("failed to parse CA certificate PEM")
	}
	return pool, nil
}

// VerifyClientCert validates a client certificate against the CA pool
// and returns the parsed identity. This is the core verification function.
func VerifyClientCert(cert *x509.Certificate, caPool *x509.CertPool) (*Identity, error) {
	opts := x509.VerifyOptions{
		Roots:     caPool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	if _, err := cert.Verify(opts); err != nil {
		return nil, fmt.Errorf("certificate verification failed: %w", err)
	}

	return ParseIdentity(cert)
}

// VerifyScopeSubset checks that child scopes are a subset of parent scopes.
// This enforces the 008 scope attenuation property: each delegation level
// can only restrict, never widen.
func VerifyScopeSubset(parent, child []string) bool {
	parentSet := make(map[string]bool, len(parent))
	for _, s := range parent {
		parentSet[s] = true
	}
	for _, s := range child {
		if !parentSet[s] {
			return false
		}
	}
	return true
}

// ── ASN.1 helpers ───────────────────────────────────────────────────────────

// parseScopeSequence parses ASN.1 SEQUENCE OF UTF8String from raw extension bytes.
func parseScopeSequence(raw []byte) ([]string, error) {
	var inner asn1.RawValue
	rest, err := asn1.Unmarshal(raw, &inner)
	if err != nil {
		return nil, err
	}
	_ = rest

	if inner.Tag != asn1.TagSequence {
		return nil, fmt.Errorf("expected SEQUENCE, got tag %d", inner.Tag)
	}

	var scopes []string
	data := inner.Bytes
	for len(data) > 0 {
		var s string
		data, err = asn1.Unmarshal(data, &s)
		if err != nil {
			return nil, err
		}
		scopes = append(scopes, s)
	}
	return scopes, nil
}

func parseUTF8String(raw []byte) (string, error) {
	var s string
	_, err := asn1.Unmarshal(raw, &s)
	return s, err
}

func parseInteger(raw []byte) (int, error) {
	var n int
	_, err := asn1.Unmarshal(raw, &n)
	return n, err
}

