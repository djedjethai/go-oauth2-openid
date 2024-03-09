package manage

import (
	"testing"
	"time"
)

func TestNewDefaultManagerWithoutCodeDuration(t *testing.T) {
	_ = NewDefaultManager()

	if DefaultAuthorizeCodeTokenCfg.AccessTokenExp != time.Hour*time.Duration(authorizeCodeTokenCfgAccessDefault) {
		t.Error("invalid default access token")
	}

	if DefaultAuthorizeCodeTokenCfg.RefreshTokenExp != time.Hour*time.Duration(authorizeCodeTokenCfgRefreshDefault) {
		t.Error("invalid default refresh token")
	}

	if DefaultAuthorizeCodeAPIServerCfg.AccessTokenExp != time.Hour*time.Duration(authorizeCodeAPIServerCfgAccessDefault) {
		t.Error("invalid default access APIServer")
	}

	if DefaultAuthorizeCodeAPIServerCfg.RefreshTokenExp != time.Hour*time.Duration(authorizeCodeAPIServerCfgRefreshDefault) {
		t.Error("invalid default refresh APIServer")
	}
}

func TestNewDefaultManagerWithCodeDuration(t *testing.T) {

	var tokenAccess int = 24
	var tokenRefresh int = 24 * 30
	var APIServerAccess int = 24 * 60
	var APIServerRefresh int = 24 * 90

	mg := ManagerConfig{
		AuthorizeCodeTokenCfgAccess:      tokenAccess,
		AuthorizeCodeTokenCfgRefresh:     tokenRefresh,
		AuthorizeCodeAPIServerCfgAccess:  APIServerAccess,
		AuthorizeCodeAPIServerCfgRefresh: APIServerRefresh,
	}

	_ = NewDefaultManager(mg)

	if DefaultAuthorizeCodeTokenCfg.AccessTokenExp != time.Hour*time.Duration(tokenAccess) {
		t.Error("invalid default access token")
	}

	if DefaultAuthorizeCodeTokenCfg.RefreshTokenExp != time.Hour*time.Duration(tokenRefresh) {
		t.Error("invalid default refresh token")
	}

	if DefaultAuthorizeCodeAPIServerCfg.AccessTokenExp != time.Hour*time.Duration(APIServerAccess) {
		t.Error("invalid default access APIServer")
	}

	if DefaultAuthorizeCodeAPIServerCfg.RefreshTokenExp != time.Hour*time.Duration(APIServerRefresh) {
		t.Error("invalid default refresh APIServer")
	}

}
