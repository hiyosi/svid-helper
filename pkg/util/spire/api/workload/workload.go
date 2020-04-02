package workload

import (
	"context"
	"time"

	"google.golang.org/grpc/metadata"
)

// PrepareAPIContext adds the security metadata header and timeout
func PrepareAPIContext(ctx context.Context, timeout time.Duration) (context.Context, func()) {
	header := metadata.Pairs("workload.spiffe.io", "true")
	ctx = metadata.NewOutgoingContext(ctx, header)
	if timeout > 0 {
		return context.WithTimeout(ctx, timeout)
	}
	return ctx, func() {}
}
