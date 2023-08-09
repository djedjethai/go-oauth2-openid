package oauth2

import (
	"context"
	"net/http"
	"time"
)

type (
	// GenerateBasic provide the basis of the generated token data
	GenerateBasic struct {
		Client    ClientInfo
		UserID    string
		CreateAt  time.Time
		TokenInfo TokenInfo
		Request   *http.Request
	}

	// AuthorizeGenerate generate the authorization code interface
	AuthorizeGenerate interface {
		Token(ctx context.Context, data *GenerateBasic) (code string, err error)
	}

	// AccessGenerate generate the access and refresh tokens interface
	AccessGenerate interface {
		Token(ctx context.Context, data *GenerateBasic, isGenRefresh bool) (access, refresh string, err error)
	}

	JWTAccessGenerate interface {
		SetJWTAccessGenerate(kid string, key []byte, meth ...string)
		// AddOpenidToClaim(claims *JWTAccessClaims, ti oauth2.TokenInfo, userInfo interface{}, isGenRefresh bool) (string, string, error)
		TokenOpenid(ctx context.Context, tokenInfo TokenInfo, isGenRefresh bool, openidInfo OpenidInfo) (string, string, error)
		ValidOpenidToken(ctx context.Context, secret string, tokenSecret string) bool
		Token(ctx context.Context, data *GenerateBasic, isGenRefresh bool) (string, string, error)
	}
)
