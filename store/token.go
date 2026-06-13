package store

import (
	"context"
	"encoding/json"
	"time"

	oauth2 "github.com/djedjethai/go-oauth2-openid"
	"github.com/djedjethai/go-oauth2-openid/models"
	"github.com/google/uuid"
	"github.com/tidwall/buntdb"
)

// NewMemoryTokenStore create a token store instance based on memory
func NewMemoryTokenStore() (oauth2.TokenStore, error) {
	return NewFileTokenStore(":memory:")
}

// NewFileTokenStore create a token store instance based on file
func NewFileTokenStore(filename string) (oauth2.TokenStore, error) {
	db, err := buntdb.Open(filename)
	if err != nil {
		return nil, err
	}
	return &TokenStore{db: db}, nil
}

// TokenStore token storage based on buntdb(https://github.com/tidwall/buntdb)
type TokenStore struct {
	db *buntdb.DB
}

type BasicData struct {
	Service string `json:"service"`
	Jv      string `json:"jv"`
}

// Create create and store the new token information
func (ts *TokenStore) Create(ctx context.Context, info oauth2.TokenInfo) error {
	ct := time.Now()
	jv, err := json.Marshal(info)
	if err != nil {
		return err
	}

	cid := info.GetClientID()
	uid := info.GetUserID()
	var svcName = ""
	if cid != "" {
		svcName = cid
	}
	if uid != "" {
		svcName = uid
	}
	bd := BasicData{
		Service: svcName,
		Jv:      string(jv),
	}
	bdJSON, err := json.Marshal(bd)
	if err != nil {
		return err
	}

	err = ts.db.Update(func(tx *buntdb.Tx) error {
		if code := info.GetCode(); code != "" {
			_, _, err := tx.Set(code, string(bdJSON), &buntdb.SetOptions{Expires: true, TTL: info.GetCodeExpiresIn()})
			return err
		}

		basicID := uuid.Must(uuid.NewRandom()).String()
		aexp := info.GetAccessExpiresIn()
		rexp := aexp
		expires := true
		if refresh := info.GetRefresh(); refresh != "" {
			rexp = info.GetRefreshCreateAt().Add(info.GetRefreshExpiresIn()).Sub(ct)
			if aexp.Seconds() > rexp.Seconds() {
				aexp = rexp
			}
			expires = info.GetRefreshExpiresIn() != 0
			_, _, err := tx.Set(refresh, basicID, &buntdb.SetOptions{Expires: expires, TTL: rexp})
			if err != nil {
				return err
			}
		}

		_, _, err = tx.Set(basicID, string(bdJSON), &buntdb.SetOptions{Expires: expires, TTL: rexp})
		if err != nil {
			return err
		}
		_, _, err = tx.Set(info.GetAccess(), basicID, &buntdb.SetOptions{Expires: expires, TTL: aexp})

		return err
	})

	return err
}

// remove key
func (ts *TokenStore) remove(key string) error {
	err := ts.db.Update(func(tx *buntdb.Tx) error {
		_, err := tx.Delete(key)
		return err
	})
	if err == buntdb.ErrNotFound {
		return nil
	}
	return err
}

// RemoveByCode use the authorization code to delete the token information
func (ts *TokenStore) RemoveByCode(ctx context.Context, code string) error {
	return ts.remove(code)
}

// RemoveByAccess use the access token to delete the token information
func (ts *TokenStore) RemoveByAccess(ctx context.Context, access string) error {
	return ts.remove(access)
}

// RemoveByRefresh use the refresh token to delete the token information
func (ts *TokenStore) RemoveByRefresh(ctx context.Context, refresh string) error {
	return ts.remove(refresh)
}

func (ts *TokenStore) RemoveAllTokensByAccess(ctx context.Context, access string) error {
	basicID, err := ts.getBasicID(access)
	if err != nil && basicID == "" {
		return err
	}

	ti, err := ts.getData(basicID)
	if err != nil {
		return err
	}

	err = ts.remove(access)
	err = ts.remove(ti.GetRefresh())
	err = ts.remove(basicID)

	return err
}

func (ts *TokenStore) RemoveAllTokensByRefresh(ctx context.Context, refresh string) error {
	basicID, err := ts.getBasicID(refresh)
	if err != nil && basicID == "" {
		return err
	}

	ti, err := ts.getData(basicID)
	if err != nil {
		return err
	}

	err = ts.remove(refresh)
	err = ts.remove(ti.GetAccess())
	err = ts.remove(basicID)

	return err
}

// RemoveByService remove the entry, based on the service name
func (ts *TokenStore) RemoveByService(ctx context.Context, svcName string) (err error) {
	var kk string

	err = ts.db.View(func(tx *buntdb.Tx) error {
		return tx.Ascend("", func(key, val string) bool {

			var bd BasicData
			if err := json.Unmarshal([]byte(val), &bd); err != nil {
				// return true // skip bad records
			}

			if bd.Service == svcName {
				kk = key
			}

			return true
		})
	})

	if kk != "" {
		_ = ts.RemoveByCode(ctx, kk)
	}

	return
}

func (ts *TokenStore) getData(key string) (oauth2.TokenInfo, error) {
	var ti oauth2.TokenInfo
	err := ts.db.View(func(tx *buntdb.Tx) error {
		val, err := tx.Get(key)
		if err != nil {
			return err
		}

		var bd BasicData
		err = json.Unmarshal([]byte(val), &bd)
		if err != nil {
			return err
		}

		var tm models.Token
		err = json.Unmarshal([]byte(bd.Jv), &tm)
		if err != nil {
			return err
		}
		ti = &tm
		return nil
	})
	if err != nil {
		if err == buntdb.ErrNotFound {
			return nil, nil
		}
		return nil, err
	}
	return ti, nil
}

func (ts *TokenStore) getBasicID(key string) (string, error) {
	var basicID string
	err := ts.db.View(func(tx *buntdb.Tx) error {
		v, err := tx.Get(key)
		if err != nil {
			return err
		}
		basicID = v
		return nil
	})
	if err != nil {
		if err == buntdb.ErrNotFound {
			return "", nil
		}
		return "", err
	}
	return basicID, nil
}

// GetByCode use the authorization code for token information data
func (ts *TokenStore) GetByCode(ctx context.Context, code string) (oauth2.TokenInfo, error) {
	return ts.getData(code)
}

// GetByAccess use the access token for token information data
func (ts *TokenStore) GetByAccess(ctx context.Context, access string) (oauth2.TokenInfo, error) {
	basicID, err := ts.getBasicID(access)
	if err != nil {
		return nil, err
	}
	return ts.getData(basicID)
}

// GetByRefresh use the refresh token for token information data
func (ts *TokenStore) GetByRefresh(ctx context.Context, refresh string) (oauth2.TokenInfo, error) {
	basicID, err := ts.getBasicID(refresh)
	if err != nil {
		return nil, err
	}
	return ts.getData(basicID)
}
