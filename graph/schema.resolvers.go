package graph

// This file will be automatically regenerated based on the schema, any resolver implementations
// will be copied through when generating and any unknown code will be moved to the end.

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/jdharms/threat-detect/graph/generated"
	"github.com/jdharms/threat-detect/graph/model"
)

func (r *mutationResolver) Enqueue(ctx context.Context, ip []string) (*model.EnqueuePayload, error) {
	queued := []string{}
	for _, addr := range ip {
		res, err := r.DNSBL.Query(addr)
		if err != nil {
			return nil, err
		}

		err = r.Adder.AddIPDetails(model.IPDetails{
			UUID:         uuid.New().String(),
			CreatedAt:    time.Now(),
			UpdatedAt:    time.Now(),
			ResponseCode: res,
			IPAddress:    addr,
		})
		if err != nil {
			return nil, err
		}

		queued = append(queued, addr)
	}
	return &model.EnqueuePayload{
		QueuedIps: queued,
	}, nil
}

func (r *queryResolver) GetIPDetails(ctx context.Context, ip string) (*model.IPDetails, error) {
	d, err := r.Getter.GetIPDetails(ip)
	if err != nil {
		return nil, err
	}

	return &d, nil
}

// Mutation returns generated.MutationResolver implementation.
func (r *Resolver) Mutation() generated.MutationResolver { return &mutationResolver{r} }

// Query returns generated.QueryResolver implementation.
func (r *Resolver) Query() generated.QueryResolver { return &queryResolver{r} }

type mutationResolver struct{ *Resolver }
type queryResolver struct{ *Resolver }
