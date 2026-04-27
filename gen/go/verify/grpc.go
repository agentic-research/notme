package verify

import (
	"context"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// UnaryServerInterceptor returns a gRPC interceptor that extracts and verifies
// the client's notme bridge cert from the TLS peer, then places the Identity
// in the context for handlers to read via IdentityFromContext.
//
// Usage:
//
//	v, _ := verify.NewFromPEM(caPEM)
//	srv := grpc.NewServer(
//	    grpc.Creds(credentials.NewTLS(v.TLSConfig())),
//	    grpc.UnaryInterceptor(v.UnaryServerInterceptor()),
//	)
func (v *Verifier) UnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		identity, err := v.identityFromPeer(ctx)
		if err != nil {
			return nil, status.Errorf(codes.Unauthenticated, "notme: %s", err.Error())
		}

		ctx = context.WithValue(ctx, identityKey, identity)
		return handler(ctx, req)
	}
}

// StreamServerInterceptor returns a gRPC stream interceptor with the same
// behavior as UnaryServerInterceptor.
func (v *Verifier) StreamServerInterceptor() grpc.StreamServerInterceptor {
	return func(
		srv any,
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		identity, err := v.identityFromPeer(ss.Context())
		if err != nil {
			return status.Errorf(codes.Unauthenticated, "notme: %s", err.Error())
		}

		wrapped := &identityStream{
			ServerStream: ss,
			ctx:          context.WithValue(ss.Context(), identityKey, identity),
		}
		return handler(srv, wrapped)
	}
}

func (v *Verifier) identityFromPeer(ctx context.Context) (*Identity, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return nil, fmt.Errorf("no peer in context")
	}

	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return nil, fmt.Errorf("peer has no TLS info")
	}

	if len(tlsInfo.State.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no client certificate")
	}

	return VerifyClientCert(tlsInfo.State.PeerCertificates[0], v.caPool)
}

// identityStream wraps a grpc.ServerStream to inject identity into context.
type identityStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *identityStream) Context() context.Context {
	return s.ctx
}
