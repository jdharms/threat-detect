package graph

// This file will be automatically regenerated based on the schema, any resolver implementations
// will be copied through when generating and any unknown code will be moved to the end.

import (
	"context"
	"log"
	"time"

	"github.com/jdharms/threat-detect/graph/generated"
	"github.com/jdharms/threat-detect/graph/model"
)

func (r *mutationResolver) Enqueue(ctx context.Context, ip []string) (*model.EnqueuePayload, error) {
	queued := []string{}
	for _, addr := range ip {
		queued = append(queued, addr)
		go func(address string) {
			res, err := r.DNSBL.Query(address)
			if err != nil {
				log.Printf("error querying DNSBL: %s", err.Error())
				return
			}

			err = r.Adder.AddIPDetails(model.IPDetails{
				UUID:         "",
				CreatedAt:    time.Time{},
				UpdatedAt:    time.Time{},
				ResponseCode: res,
				IPAddress:    address,
			})
			if err != nil {
				log.Printf("error adding ip details: %s", err.Error())
				return
			}
		}(addr)
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
