package manage

import (
	"time"
)

// Config authorization configuration parameters
type Config struct {
	// access token expiration time, 0 means it doesn't expire
	AccessTokenExp time.Duration
	// refresh token expiration time, 0 means it doesn't expire
	RefreshTokenExp time.Duration
	// whether to generate the refreshing token
	IsGenerateRefresh bool
}

// RefreshingConfig refreshing token config
type RefreshingConfig struct {
	// access token expiration time, 0 means it doesn't expire
	AccessTokenExp time.Duration
	// refresh token expiration time, 0 means it doesn't expire
	RefreshTokenExp time.Duration
	// whether to generate the refreshing token
	IsGenerateRefresh bool
	// whether to reset the refreshing create time
	IsResetRefreshTime bool
	// whether to remove access token
	IsRemoveAccess bool
	// whether to remove refreshing token
	IsRemoveRefreshing bool
}

// default configs
var (
	DefaultCodeExp = time.Minute * 10
	// DefaultAuthorizeCodeTokenCfg = &Config{AccessTokenExp: time.Hour * 2, RefreshTokenExp: time.Hour * 24 * 15, IsGenerateRefresh: true}
	DefaultAuthorizeCodeTokenCfg *Config
	// DefaultAuthorizeCodeAPIServerTokenCfg = &Config{AccessTokenExp: time.Hour * 24 * 15, RefreshTokenExp: time.Hour * 24 * 180, IsGenerateRefresh: true}
	DefaultAuthorizeCodeAPIServerCfg *Config
	DefaultImplicitTokenCfg          = &Config{AccessTokenExp: time.Hour * 1}
	DefaultPasswordTokenCfg          = &Config{AccessTokenExp: time.Hour * 2, RefreshTokenExp: time.Hour * 24 * 7, IsGenerateRefresh: true}
	DefaultClientTokenCfg            = &Config{AccessTokenExp: time.Hour * 2}
	DefaultRefreshTokenCfg           = &RefreshingConfig{IsGenerateRefresh: true, IsRemoveAccess: true, IsRemoveRefreshing: true}
)

// ManagerConfig manage the configs for the manager
type ManagerConfig struct {
	AuthorizeCodeTokenCfgAccess      int
	AuthorizeCodeTokenCfgRefresh     int
	AuthorizeCodeAPIServerCfgAccess  int
	AuthorizeCodeAPIServerCfgRefresh int
}

func (mc ManagerConfig) SetConfigs() {
	if mc.AuthorizeCodeTokenCfgAccess > 0 &&
		mc.AuthorizeCodeTokenCfgRefresh > 0 &&
		mc.AuthorizeCodeAPIServerCfgAccess > 0 &&
		mc.AuthorizeCodeAPIServerCfgRefresh > 0 {
		NewCodeDuration(
			mc.AuthorizeCodeTokenCfgAccess,
			mc.AuthorizeCodeTokenCfgRefresh,
			mc.AuthorizeCodeAPIServerCfgAccess,
			mc.AuthorizeCodeAPIServerCfgRefresh,
		)

	} else {
		NewCodeDuration(0, 0, 0, 0)
	}
}

const (
	authorizeCodeTokenCfgAccessDefault      int = 2
	authorizeCodeTokenCfgRefreshDefault     int = 24 * 15
	authorizeCodeAPIServerCfgAccessDefault  int = 24 * 15
	authorizeCodeAPIServerCfgRefreshDefault int = 24 * 180
)

// NewCodeDuration set the tokens duration configs
func NewCodeDuration(at, rt, aa, ar int) {
	tc := NewTokenConfig(at, rt)
	DefaultAuthorizeCodeTokenCfg = &Config{
		AccessTokenExp:    time.Hour * time.Duration(tc.authorizeCodeTokenCfgAccess),
		RefreshTokenExp:   time.Hour * time.Duration(tc.authorizeCodeTokenCfgRefresh),
		IsGenerateRefresh: true}

	ac := NewAPIServerConfig(aa, ar)
	DefaultAuthorizeCodeAPIServerCfg = &Config{
		AccessTokenExp:    time.Hour * time.Duration(ac.authorizeCodeAPIServerCfgAccess),
		RefreshTokenExp:   time.Hour * time.Duration(ac.authorizeCodeAPIServerCfgRefresh),
		IsGenerateRefresh: true}

}

// tokenConfig are duration for the token, means user accounts
type tokenConfig struct {
	authorizeCodeTokenCfgAccess  int
	authorizeCodeTokenCfgRefresh int
}

func NewTokenConfig(da, dr int) *tokenConfig {
	tc := &tokenConfig{}

	tc.setAuthorizeCodeTokenCfgAccess(da)
	tc.setAuthorizeCodeTokenCfgRefresh(dr)

	return tc
}

func (t *tokenConfig) setAuthorizeCodeTokenCfgAccess(d int) {
	if d > 0 {
		t.authorizeCodeTokenCfgAccess = d
	} else {
		t.authorizeCodeTokenCfgAccess = authorizeCodeTokenCfgAccessDefault
	}
}

func (t *tokenConfig) setAuthorizeCodeTokenCfgRefresh(d int) {
	if d > 0 {
		t.authorizeCodeTokenCfgRefresh = d
	} else {
		t.authorizeCodeTokenCfgRefresh = authorizeCodeTokenCfgRefreshDefault
	}
}

// apiServerConfig are duration for the APIServer, means the api's servers account
type apiServerConfig struct {
	authorizeCodeAPIServerCfgAccess  int
	authorizeCodeAPIServerCfgRefresh int
}

func NewAPIServerConfig(da, dr int) *apiServerConfig {
	tc := &apiServerConfig{}

	tc.setAuthorizeCodeAPIServerCfgAccess(da)
	tc.setAuthorizeCodeAPIServerCfgRefresh(dr)

	return tc
}

func (t *apiServerConfig) setAuthorizeCodeAPIServerCfgAccess(d int) {
	if d > 0 {
		t.authorizeCodeAPIServerCfgAccess = d
	} else {
		t.authorizeCodeAPIServerCfgAccess = authorizeCodeAPIServerCfgAccessDefault
	}
}

func (t *apiServerConfig) setAuthorizeCodeAPIServerCfgRefresh(d int) {
	if d > 0 {
		t.authorizeCodeAPIServerCfgRefresh = d
	} else {
		t.authorizeCodeAPIServerCfgRefresh = authorizeCodeAPIServerCfgRefreshDefault
	}
}
