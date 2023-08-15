package oauth2

import (
	"context"
	// "github.com/go-oauth2/oauth2/v4"
	"net/http"
	"time"
)

// TokenGenerateRequest provide to generate the token request parameters
type TokenGenerateRequest struct {
	ClientID            string
	ClientSecret        string
	UserID              string
	RedirectURI         string
	Scope               string
	Code                string
	CodeChallenge       string
	CodeChallengeMethod CodeChallengeMethod
	Refresh             string
	CodeVerifier        string
	AccessTokenExp      time.Duration
	Request             *http.Request
}

// Manager authorization management interface
type Manager interface {
	// get the client information
	GetClient(ctx context.Context, clientID string) (cli ClientInfo, err error)

	// generate the authorization token(code)
	GenerateAuthToken(ctx context.Context, rt ResponseType, tgr *TokenGenerateRequest) (authToken TokenInfo, err error)

	// generate the access token
	GenerateAccessToken(ctx context.Context, gt GrantType, tgr *TokenGenerateRequest) (accessToken TokenInfo, err error)

	// refreshing an access token
	RefreshAccessToken(ctx context.Context, tgr *TokenGenerateRequest) (accessToken TokenInfo, err error)

	// use the access token to delete the token information
	RemoveAccessToken(ctx context.Context, access string) (err error)

	// use the refresh token to delete the token information
	RemoveRefreshToken(ctx context.Context, refresh string) (err error)

	// according to the access token for corresponding token information
	LoadAccessToken(ctx context.Context, access string) (ti TokenInfo, err error)

	// according to the refresh token for corresponding token information
	LoadRefreshToken(ctx context.Context, refresh string) (ti TokenInfo, err error)

	GenerateOpenidJWToken(ctx context.Context, ti TokenInfo, isGenRefresh bool, oInfo OpenidInfo) (string, string, error)

	RefreshOpenidJWToken(ctx context.Context, secret, token string) (string, string, error)

	SetJWTAccessGenerate(keyID string, secretKey []byte, signInMethod ...string)

	ValidOpenidJWToken(ctx context.Context, secretKey, token string) error

	GetOauthTokensFromOpenidJWToken(ctx context.Context, secretKey, token string) (OpenidInfo, string, string, error)

	RefreshTokens(ctx context.Context, refresh string) (TokenInfo, error)
}
