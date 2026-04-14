package keycloak

import "context"

type ctxKeyRequestID struct{}

// WithRequestID returns a child context carrying requestID for structured logs in KeycloakAPI methods.
func WithRequestID(ctx context.Context, requestID string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if requestID == "" {
		return ctx
	}
	return context.WithValue(ctx, ctxKeyRequestID{}, requestID)
}

func requestIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	s, _ := ctx.Value(ctxKeyRequestID{}).(string)
	return s
}
