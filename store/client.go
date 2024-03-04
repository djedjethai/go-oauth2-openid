package store

import (
	"context"
	"errors"
	"sync"

	oauth2 "github.com/djedjethai/go-oauth2-openid"
)

// NewClientStore create client store
func NewClientStore() *ClientStore {
	return &ClientStore{
		data: make(map[string]oauth2.ClientInfo),
	}
}

// ClientStore client information store
type ClientStore struct {
	sync.RWMutex
	data map[string]oauth2.ClientInfo
}

// GetByID according to the ID for the client information
func (cs *ClientStore) GetByID(ctx context.Context, id string) (oauth2.ClientInfo, error) {
	cs.RLock()
	defer cs.RUnlock()

	if c, ok := cs.data[id]; ok {
		return c, nil
	}
	return nil, errors.New("not found")
}

func (cs *ClientStore) RemoveByID(id string) error {
	cs.Lock()
	defer cs.Unlock()

	if _, ok := cs.data[id]; ok {
		delete(cs.data, id)
		return nil
	}

	return errors.New("not found")
}

func (cs *ClientStore) UpsertClientJWToken(ctx context.Context, id, JWToken string) (err error) {
	cs.Lock()
	defer cs.Unlock()

	if _, ok := cs.data[id]; ok {
		// TODO see how to add the jwt here...??
		return nil
	}

	return errors.New("not found")

}

// Set set client information
func (cs *ClientStore) Set(id string, cli oauth2.ClientInfo) (err error) {
	cs.Lock()
	defer cs.Unlock()

	cs.data[id] = cli
	return
}
