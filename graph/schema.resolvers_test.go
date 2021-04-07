package graph

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/jdharms/threat-detect/graph/model"
)

type queryChecker struct {
	wg *sync.WaitGroup
}

func (qc queryChecker) Query(ip string) (string, error) {
	qc.wg.Done()
	return "foo", nil
}

type adderChecker struct {
	repository chan model.IPDetails
	wg         *sync.WaitGroup
}

func (d *adderChecker) AddIPDetails(m model.IPDetails) error {
	d.repository <- m
	d.wg.Done()
	return nil
}

func TestEnqueue(t *testing.T) {
	// We'll test by creating a waitgroup, making our DNSBL/Details adder clients decrement it, and seeing if it finishes.
	queryWg := sync.WaitGroup{}
	queryWg.Add(3)

	adderWg := sync.WaitGroup{}
	adderWg.Add(3)

	ac := adderChecker{wg: &adderWg, repository: make(chan model.IPDetails, 3)}

	sut := Resolver{
		Adder: &ac,
		DNSBL: &queryChecker{wg: &queryWg},
	}

	ctx := context.Background()

	res, err := sut.Mutation().Enqueue(ctx, []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"})
	if len(res.QueuedIps) != 3 {
		t.Errorf("expected 3 queued ips, found %d", len(res.QueuedIps))
	}

	if err != nil {
		t.Errorf("error calling Enqueue(): %s", err.Error())
	}

	queryWg.Wait()
	adderWg.Wait()

	if len(ac.repository) != 3 {
		t.Errorf("expected to have 3 details in repository, have %d", len(ac.repository))
	}
}

type mockGetter struct {
	getFunc func(string) (model.IPDetails, error)
}

func (mg mockGetter) GetIPDetails(ip string) (model.IPDetails, error) {
	return mg.getFunc(ip)
}

func TestGetIPDetails(t *testing.T) {
	called := false

	sut := Resolver{
		Getter: mockGetter{getFunc: func(s string) (model.IPDetails, error) {
			called = true
			return model.IPDetails{IPAddress: "1.2.3.4"}, nil
		}},
	}

	ctx := context.Background()
	res, err := sut.Query().GetIPDetails(ctx, "1.2.3.4")
	if err != nil {
		t.Errorf("GetIPDetails returned unexpected error: %s", err.Error())
	}
	if res.IPAddress != "1.2.3.4" {
		t.Error("details returned by GetIPDetails are incorrect or malformed")
	}

	if !called {
		t.Error("Resolver's Getter was not called")
	}
}

func TestGetIPDetailsReturnsError(t *testing.T) {
	called := false

	sut := Resolver{
		Getter: mockGetter{getFunc: func(s string) (model.IPDetails, error) {
			called = true
			return model.IPDetails{}, fmt.Errorf("some error")
		}},
	}

	ctx := context.Background()
	res, err := sut.Query().GetIPDetails(ctx, "1.2.3.4")
	if !called {
		t.Error("Resolver's Getter was not called")
	}
	if res != nil {
		t.Error("expected error result of GetIPDetails to be nil--leaking info?")
	}
	if !strings.Contains(err.Error(), "error") {
		t.Error("expected an error result from GetIPDetails")
	}
}
