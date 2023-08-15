package manage

import (
	"context"
	"log"
	"time"

	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/errors"
	"github.com/go-oauth2/oauth2/v4/generates"
	"github.com/go-oauth2/oauth2/v4/models"
	// "github.com/golang-jwt/jwt/v4"
)

// NewDefaultManager create to default authorization management instance
func NewDefaultManager() *Manager {
	m := NewManager()
	// default implementation
	m.MapAuthorizeGenerate(generates.NewAuthorizeGenerate())
	m.MapAccessGenerate(generates.NewAccessGenerate())
	m.MapJWTAccessGenerate(generates.NewDefaultJWTAccessGenerate())

	return m
}

// NewManager create to authorization management instance
func NewManager() *Manager {
	return &Manager{
		gtcfg:       make(map[oauth2.GrantType]*Config),
		validateURI: DefaultValidateURI,
	}
}

// Manager provide authorization management
type Manager struct {
	codeExp           time.Duration
	gtcfg             map[oauth2.GrantType]*Config
	rcfg              *RefreshingConfig
	validateURI       ValidateURIHandler
	authorizeGenerate oauth2.AuthorizeGenerate
	accessGenerate    oauth2.AccessGenerate
	jwtAccessGenerate oauth2.JWTAccessGenerate
	tokenStore        oauth2.TokenStore
	clientStore       oauth2.ClientStore
}

// get grant type config
func (m *Manager) grantConfig(gt oauth2.GrantType) *Config {
	if c, ok := m.gtcfg[gt]; ok && c != nil {
		return c
	}
	switch gt {
	case oauth2.AuthorizationCode:
		return DefaultAuthorizeCodeTokenCfg
	case oauth2.Implicit:
		return DefaultImplicitTokenCfg
	case oauth2.PasswordCredentials:
		return DefaultPasswordTokenCfg
	case oauth2.ClientCredentials:
		return DefaultClientTokenCfg
	}
	return &Config{}
}

// TODO craete UserInfo
// func (m *Manager) GenerateOpenidJWT(ctx context.Context, ti oauth2.TokenInfo, isGenRefresh bool, uInfo oauth2.UserInfo) (string, string, error) {
func (m *Manager) GenerateOpenidJWToken(ctx context.Context, ti oauth2.TokenInfo, isGenRefresh bool, oInfo oauth2.OpenidInfo) (string, string, error) {
	// TODO create a userInfo struct

	// TODO see if m.accessGenerate is not already called
	return m.jwtAccessGenerate.GenerateOpenidJWToken(ctx, ti, isGenRefresh, oInfo)

}

func (m *Manager) SetJWTAccessGenerate(kid string, key []byte, meth ...string) {
	m.jwtAccessGenerate.SetJWTAccessGenerate(kid, key, meth...)
}
func (m *Manager) RefreshOpenidJWToken(ctx context.Context, secretKey, token string) (string, string, error) {
	return m.RefreshOpenidJWToken(ctx, secretKey, token)
}

func (m *Manager) ValidOpenidJWToken(ctx context.Context, secretKey, token string) error {
	return m.jwtAccessGenerate.ValidOpenidJWToken(ctx, secretKey, token)
}

func (m *Manager) GetOauthTokensFromOpenidJWToken(ctx context.Context, secretKey, token string) (oauth2.OpenidInfo, string, string, error) {
	return m.jwtAccessGenerate.GetOauthTokensFromOpenidJWToken(ctx, secretKey, token)
}

func (m *Manager) MapJWTAccessGenerate(gen oauth2.JWTAccessGenerate) {
	m.jwtAccessGenerate = gen
}

//
func (m *Manager) RefreshTokens(ctx context.Context, refresh string) (oauth2.TokenInfo, error) {
	//get basicID ti from refersh db
	ti, err := m.tokenStore.GetByRefresh(ctx, refresh)
	if err != nil {
		log.Println("manager.go RefreshTokens err: ", err)
		return nil, err
	}

	log.Println("manager.go RefreshTokens ti: ", ti)

	// USE the ti info to Generate new AccessToken and refreshTk
	// then m.GenerateAccessToken(ctx, gt, gtx)
	// it seems to me that gt and gtx are inside ti..?

	// return the new ti(with refreshed info)
	return ti, nil

}

// SetAuthorizeCodeExp set the authorization code expiration time
func (m *Manager) SetAuthorizeCodeExp(exp time.Duration) {
	m.codeExp = exp
}

// SetAuthorizeCodeTokenCfg set the authorization code grant token config
func (m *Manager) SetAuthorizeCodeTokenCfg(cfg *Config) {
	m.gtcfg[oauth2.AuthorizationCode] = cfg
}

// SetImplicitTokenCfg set the implicit grant token config
func (m *Manager) SetImplicitTokenCfg(cfg *Config) {
	m.gtcfg[oauth2.Implicit] = cfg
}

// SetPasswordTokenCfg set the password grant token config
func (m *Manager) SetPasswordTokenCfg(cfg *Config) {
	m.gtcfg[oauth2.PasswordCredentials] = cfg
}

// SetClientTokenCfg set the client grant token config
func (m *Manager) SetClientTokenCfg(cfg *Config) {
	m.gtcfg[oauth2.ClientCredentials] = cfg
}

// SetRefreshTokenCfg set the refreshing token config
func (m *Manager) SetRefreshTokenCfg(cfg *RefreshingConfig) {
	m.rcfg = cfg
}

// SetValidateURIHandler set the validates that RedirectURI is contained in baseURI
func (m *Manager) SetValidateURIHandler(handler ValidateURIHandler) {
	m.validateURI = handler
}

// MapAuthorizeGenerate mapping the authorize code generate interface
func (m *Manager) MapAuthorizeGenerate(gen oauth2.AuthorizeGenerate) {
	m.authorizeGenerate = gen
}

// MapAccessGenerate mapping the access token generate interface
func (m *Manager) MapAccessGenerate(gen oauth2.AccessGenerate) {
	m.accessGenerate = gen
}

// MapClientStorage mapping the client store interface
func (m *Manager) MapClientStorage(stor oauth2.ClientStore) {
	m.clientStore = stor
}

// MustClientStorage mandatory mapping the client store interface
func (m *Manager) MustClientStorage(stor oauth2.ClientStore, err error) {
	if err != nil {
		panic(err.Error())
	}
	m.clientStore = stor
}

// MapTokenStorage mapping the token store interface
func (m *Manager) MapTokenStorage(stor oauth2.TokenStore) {
	m.tokenStore = stor
}

// MustTokenStorage mandatory mapping the token store interface
func (m *Manager) MustTokenStorage(stor oauth2.TokenStore, err error) {
	if err != nil {
		panic(err)
	}
	m.tokenStore = stor
}

// GetClient get the client information
func (m *Manager) GetClient(ctx context.Context, clientID string) (cli oauth2.ClientInfo, err error) {
	cli, err = m.clientStore.GetByID(ctx, clientID)
	if err != nil {
		return
	} else if cli == nil {
		err = errors.ErrInvalidClient
	}
	return
}

// GenerateAuthToken generate the authorization token(code)
func (m *Manager) GenerateAuthToken(ctx context.Context, rt oauth2.ResponseType, tgr *oauth2.TokenGenerateRequest) (oauth2.TokenInfo, error) {
	cli, err := m.GetClient(ctx, tgr.ClientID)
	if err != nil {
		return nil, err
	} else if tgr.RedirectURI != "" {
		if err := m.validateURI(cli.GetDomain(), tgr.RedirectURI); err != nil {
			return nil, err
		}
	}

	ti := models.NewToken()
	ti.SetClientID(tgr.ClientID)
	ti.SetUserID(tgr.UserID)
	ti.SetRedirectURI(tgr.RedirectURI)
	ti.SetScope(tgr.Scope)

	createAt := time.Now()
	td := &oauth2.GenerateBasic{
		Client:    cli,
		UserID:    tgr.UserID,
		CreateAt:  createAt,
		TokenInfo: ti,
		Request:   tgr.Request,
	}
	switch rt {
	case oauth2.Code:
		codeExp := m.codeExp
		if codeExp == 0 {
			codeExp = DefaultCodeExp
		}
		ti.SetCodeCreateAt(createAt)
		ti.SetCodeExpiresIn(codeExp)
		if exp := tgr.AccessTokenExp; exp > 0 {
			ti.SetAccessExpiresIn(exp)
		}
		if tgr.CodeChallenge != "" {
			ti.SetCodeChallenge(tgr.CodeChallenge)
			ti.SetCodeChallengeMethod(tgr.CodeChallengeMethod)
		}

		tv, err := m.authorizeGenerate.Token(ctx, td)
		log.Println("manager.go in oauth2.Code, see tv: ", tv)

		if err != nil {
			return nil, err
		}
		ti.SetCode(tv)
	case oauth2.Token:
		log.Println("manager.go in oauth2.Token(...................")
		// set access token expires
		icfg := m.grantConfig(oauth2.Implicit)
		aexp := icfg.AccessTokenExp
		if exp := tgr.AccessTokenExp; exp > 0 {
			aexp = exp
		}
		ti.SetAccessCreateAt(createAt)
		ti.SetAccessExpiresIn(aexp)

		if icfg.IsGenerateRefresh {
			ti.SetRefreshCreateAt(createAt)
			ti.SetRefreshExpiresIn(icfg.RefreshTokenExp)
		}

		tv, rv, err := m.accessGenerate.Token(ctx, td, icfg.IsGenerateRefresh)
		if err != nil {
			return nil, err
		}
		ti.SetAccess(tv)

		if rv != "" {
			ti.SetRefresh(rv)
		}
	}

	err = m.tokenStore.Create(ctx, ti)
	if err != nil {
		return nil, err
	}
	return ti, nil
}

// get authorization code data
func (m *Manager) getAuthorizationCode(ctx context.Context, code string) (oauth2.TokenInfo, error) {

	log.Println("in getAuthorizationCode code: ", code)
	ti, err := m.tokenStore.GetByCode(ctx, code)
	log.Println("in getAuthorizationCode: ", ti, " - error: ", err)
	if err != nil {
		return nil, err
	} else if ti == nil || ti.GetCode() != code || ti.GetCodeCreateAt().Add(ti.GetCodeExpiresIn()).Before(time.Now()) {
		err = errors.ErrInvalidAuthorizeCode
		return nil, errors.ErrInvalidAuthorizeCode
	}
	return ti, nil
}

// delete authorization code data
func (m *Manager) delAuthorizationCode(ctx context.Context, code string) error {
	return m.tokenStore.RemoveByCode(ctx, code)
}

// get and delete authorization code data
func (m *Manager) getAndDelAuthorizationCode(ctx context.Context, tgr *oauth2.TokenGenerateRequest) (oauth2.TokenInfo, error) {
	log.Println("see tgr: ", tgr)
	code := tgr.Code

	log.Println("see tgr code: ", code)
	ti, err := m.getAuthorizationCode(ctx, code)
	log.Println("see ti: ", ti)
	log.Println("see ti err: ", err)
	if err != nil {
		return nil, err
	} else if ti.GetClientID() != tgr.ClientID {
		return nil, errors.ErrInvalidAuthorizeCode
	} else if codeURI := ti.GetRedirectURI(); codeURI != "" && codeURI != tgr.RedirectURI {
		return nil, errors.ErrInvalidAuthorizeCode
	}

	err = m.delAuthorizationCode(ctx, code)
	if err != nil {
		log.Println("error in delAuthorizationCode: ", err)
		return nil, err
	}
	log.Println("See the ti: ", ti)
	return ti, nil
}

func (m *Manager) validateCodeChallenge(ti oauth2.TokenInfo, ver string) error {
	cc := ti.GetCodeChallenge()
	// early return
	if cc == "" && ver == "" {
		return nil
	}
	if cc == "" {
		return errors.ErrMissingCodeVerifier
	}
	if ver == "" {
		return errors.ErrMissingCodeVerifier
	}
	ccm := ti.GetCodeChallengeMethod()
	if ccm.String() == "" {
		ccm = oauth2.CodeChallengePlain
	}
	if !ccm.Validate(cc, ver) {
		return errors.ErrInvalidCodeChallenge
	}
	return nil
}

// GenerateAccessToken generate the access token
func (m *Manager) GenerateAccessToken(ctx context.Context, gt oauth2.GrantType, tgr *oauth2.TokenGenerateRequest) (oauth2.TokenInfo, error) {
	log.Println("manager.go GenerateAccessToken tg:... ", gt)
	log.Println("manager.go GenerateAccessToken tgr:... ", tgr)
	cli, err := m.GetClient(ctx, tgr.ClientID)
	if err != nil {
		return nil, err
	}
	if cliPass, ok := cli.(oauth2.ClientPasswordVerifier); ok {
		if !cliPass.VerifyPassword(tgr.ClientSecret) {
			return nil, errors.ErrInvalidClient
		}
	} else if len(cli.GetSecret()) > 0 && tgr.ClientSecret != cli.GetSecret() {
		return nil, errors.ErrInvalidClient
	}
	if tgr.RedirectURI != "" {
		if err := m.validateURI(cli.GetDomain(), tgr.RedirectURI); err != nil {
			return nil, err
		}
	}

	if gt == oauth2.ClientCredentials && cli.IsPublic() == true {
		return nil, errors.ErrInvalidClient
	}

	log.Println("seee the oauth2.AuthorizationCode: ", oauth2.AuthorizationCode)

	if gt == oauth2.AuthorizationCode {
		log.Println("grrrrrrrr")
		ti, err := m.getAndDelAuthorizationCode(ctx, tgr)
		if err != nil {
			return nil, err
		}
		log.Println("manager.go GenerateAccessToken12:... ")
		if err := m.validateCodeChallenge(ti, tgr.CodeVerifier); err != nil {
			return nil, err
		}

		tgr.UserID = ti.GetUserID()
		tgr.Scope = ti.GetScope()
		if exp := ti.GetAccessExpiresIn(); exp > 0 {
			tgr.AccessTokenExp = exp
		}
	}

	ti := models.NewToken()
	ti.SetClientID(tgr.ClientID)
	ti.SetUserID(tgr.UserID)
	ti.SetRedirectURI(tgr.RedirectURI)
	ti.SetScope(tgr.Scope)

	createAt := time.Now()
	ti.SetAccessCreateAt(createAt)

	// set access token expires
	gcfg := m.grantConfig(gt)
	aexp := gcfg.AccessTokenExp
	if exp := tgr.AccessTokenExp; exp > 0 {
		aexp = exp
	}
	ti.SetAccessExpiresIn(aexp)
	if gcfg.IsGenerateRefresh {
		ti.SetRefreshCreateAt(createAt)
		ti.SetRefreshExpiresIn(gcfg.RefreshTokenExp)
	}

	td := &oauth2.GenerateBasic{
		Client:    cli,
		UserID:    tgr.UserID,
		CreateAt:  createAt,
		TokenInfo: ti,
		Request:   tgr.Request,
	}

	av, rv, err := m.accessGenerate.Token(ctx, td, gcfg.IsGenerateRefresh)
	log.Println("manager.go this is the token: ", av)
	if err != nil {
		return nil, err
	}
	ti.SetAccess(av)

	if rv != "" {
		ti.SetRefresh(rv)
	}

	log.Println("manager.go generate access token:.... ", ti)
	err = m.tokenStore.Create(ctx, ti)
	if err != nil {
		return nil, err
	}
	log.Println("The token store is not activate look like........")

	return ti, nil
}

// RefreshAccessToken refreshing an access token
func (m *Manager) RefreshAccessToken(ctx context.Context, tgr *oauth2.TokenGenerateRequest) (oauth2.TokenInfo, error) {
	ti, err := m.LoadRefreshToken(ctx, tgr.Refresh)
	if err != nil {
		return nil, err
	}

	cli, err := m.GetClient(ctx, ti.GetClientID())
	if err != nil {
		return nil, err
	}

	oldAccess, oldRefresh := ti.GetAccess(), ti.GetRefresh()

	td := &oauth2.GenerateBasic{
		Client:    cli,
		UserID:    ti.GetUserID(),
		CreateAt:  time.Now(),
		TokenInfo: ti,
		Request:   tgr.Request,
	}

	rcfg := DefaultRefreshTokenCfg
	if v := m.rcfg; v != nil {
		rcfg = v
	}

	ti.SetAccessCreateAt(td.CreateAt)
	if v := rcfg.AccessTokenExp; v > 0 {
		ti.SetAccessExpiresIn(v)
	}

	if v := rcfg.RefreshTokenExp; v > 0 {
		ti.SetRefreshExpiresIn(v)
	}

	if rcfg.IsResetRefreshTime {
		ti.SetRefreshCreateAt(td.CreateAt)
	}

	if scope := tgr.Scope; scope != "" {
		ti.SetScope(scope)
	}

	tv, rv, err := m.accessGenerate.Token(ctx, td, rcfg.IsGenerateRefresh)
	if err != nil {
		return nil, err
	}

	ti.SetAccess(tv)
	if rv != "" {
		ti.SetRefresh(rv)
	}

	if err := m.tokenStore.Create(ctx, ti); err != nil {
		return nil, err
	}

	if rcfg.IsRemoveAccess {
		// remove the old access token
		if err := m.tokenStore.RemoveByAccess(ctx, oldAccess); err != nil {
			return nil, err
		}
	}

	if rcfg.IsRemoveRefreshing && rv != "" {
		// remove the old refresh token
		if err := m.tokenStore.RemoveByRefresh(ctx, oldRefresh); err != nil {
			return nil, err
		}
	}

	if rv == "" {
		ti.SetRefresh("")
		ti.SetRefreshCreateAt(time.Now())
		ti.SetRefreshExpiresIn(0)
	}

	return ti, nil
}

// RemoveAccessToken use the access token to delete the token information
func (m *Manager) RemoveAccessToken(ctx context.Context, access string) error {
	if access == "" {
		return errors.ErrInvalidAccessToken
	}
	return m.tokenStore.RemoveByAccess(ctx, access)
}

// RemoveRefreshToken use the refresh token to delete the token information
func (m *Manager) RemoveRefreshToken(ctx context.Context, refresh string) error {
	if refresh == "" {
		return errors.ErrInvalidAccessToken
	}
	return m.tokenStore.RemoveByRefresh(ctx, refresh)
}

// LoadAccessToken according to the access token for corresponding token information
func (m *Manager) LoadAccessToken(ctx context.Context, access string) (oauth2.TokenInfo, error) {
	log.Println("manager.go load by access")
	if access == "" {
		return nil, errors.ErrInvalidAccessToken
	}

	ct := time.Now()
	ti, err := m.tokenStore.GetByAccess(ctx, access)
	if err != nil {
		return nil, err
	} else if ti == nil || ti.GetAccess() != access {
		return nil, errors.ErrInvalidAccessToken
	} else if ti.GetRefresh() != "" && ti.GetRefreshExpiresIn() != 0 &&
		ti.GetRefreshCreateAt().Add(ti.GetRefreshExpiresIn()).Before(ct) {
		return nil, errors.ErrExpiredRefreshToken
	} else if ti.GetAccessExpiresIn() != 0 &&
		ti.GetAccessCreateAt().Add(ti.GetAccessExpiresIn()).Before(ct) {
		return nil, errors.ErrExpiredAccessToken
	}
	return ti, nil
}

// LoadRefreshToken according to the refresh token for corresponding token information
func (m *Manager) LoadRefreshToken(ctx context.Context, refresh string) (oauth2.TokenInfo, error) {
	if refresh == "" {
		return nil, errors.ErrInvalidRefreshToken
	}

	ti, err := m.tokenStore.GetByRefresh(ctx, refresh)
	if err != nil {
		return nil, err
	} else if ti == nil || ti.GetRefresh() != refresh {
		return nil, errors.ErrInvalidRefreshToken
	} else if ti.GetRefreshExpiresIn() != 0 && // refresh token set to not expire
		ti.GetRefreshCreateAt().Add(ti.GetRefreshExpiresIn()).Before(time.Now()) {
		return nil, errors.ErrExpiredRefreshToken
	}
	return ti, nil
}
