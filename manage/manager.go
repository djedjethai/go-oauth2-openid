package manage

import (
	"context"
	"time"

	oauth2 "github.com/djedjethai/go-oauth2-openid"
	"github.com/djedjethai/go-oauth2-openid/errors"
	"github.com/djedjethai/go-oauth2-openid/generates"
	"github.com/djedjethai/go-oauth2-openid/models"
)

// NewDefaultManager create to default authorization management instance
func NewDefaultManager(mc ...ManagerConfig) *Manager {
	m := NewManager(mc...)

	// default implementation
	m.MapAuthorizeGenerate(generates.NewAuthorizeGenerate())
	m.MapAccessGenerate(generates.NewAccessGenerate())
	m.MapJWTAccessGenerate(generates.NewDefaultJWTAccessGenerate())

	return m
}

// NewManager create to authorization management instance
func NewManager(mc ...ManagerConfig) *Manager {
	// set the Manager configuration
	if len(mc) > 0 {
		mc[0].SetConfigs()
	} else {
		ManagerConfig{}.SetConfigs()
	}

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

// NOTE NOTE
// get grant type config
func (m *Manager) grantConfig(gt oauth2.GrantType, role ...string) *Config {
	if c, ok := m.gtcfg[gt]; ok && c != nil {
		return c
	}
	switch gt {
	case oauth2.AuthorizationCode:
		if len(role) > 0 {
			switch role[0] {
			case "APIserver":
				return DefaultAuthorizeCodeAPIServerCfg
			}
		}
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

// CreateJWTAccessGenerate return a JWTAccessGenerate instance
func (m *Manager) CreateJWTAccessGenerate(kid string, key []byte, meth ...string) oauth2.JWTAccessGenerate {
	return m.jwtAccessGenerate.CreateJWTAccessGenerate(kid, key, meth...)
}

// MapJWTAccessGenerate give to the manager an access to the JWTAccessGenerate
func (m *Manager) MapJWTAccessGenerate(gen oauth2.JWTAccessGenerate) {
	m.jwtAccessGenerate = gen
}

// RefreshTokens return TokenInfo linked with the refreshToken
func (m *Manager) RefreshTokens(ctx context.Context, refresh string) (oauth2.TokenInfo, error) {
	//get basicID ti from refersh db
	ti, err := m.tokenStore.GetByRefresh(ctx, refresh)
	if err != nil {
		return nil, err
	}

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

// UpsertClientJWToken aim to store JWT into clientStore Account for APIServer
func (m *Manager) UpsertClientJWToken(ctx context.Context, clientID, JWToken string) (err error) {
	err = m.clientStore.UpsertClientJWToken(ctx, clientID, JWToken)
	if err != nil {
		return
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

		if err != nil {
			return nil, err
		}
		ti.SetCode(tv)

	case oauth2.Token:
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

// NOTE  ....
// get authorization code data
func (m *Manager) getAuthorizationCode(ctx context.Context, code string) (oauth2.TokenInfo, error) {
	ti, err := m.tokenStore.GetByCode(ctx, code)
	// fmt.Println("manager.go - getAuthorizationCode err: ", err, "  - ", ti)
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

// NOTE ....
// get and delete authorization code data
func (m *Manager) getAndDelAuthorizationCode(ctx context.Context, tgr *oauth2.TokenGenerateRequest) (oauth2.TokenInfo, error) {
	code := tgr.Code

	// fmt.Println("manager.go - getAndDelAuthorizationCode see the code: ", code)

	ti, err := m.getAuthorizationCode(ctx, code)
	// fmt.Println("manager.go - getAndDelAuthorizationCode: ", err, " - ", ti)
	if err != nil {
		return nil, err
	} else if ti.GetClientID() != tgr.ClientID {
		return nil, errors.ErrInvalidAuthorizeCode
	} else if codeURI := ti.GetRedirectURI(); codeURI != "" && codeURI != tgr.RedirectURI {
		return nil, errors.ErrInvalidAuthorizeCode
	}

	// fmt.Println("manager.go - getAndDelAuthorizationCode: ", ti.GetRedirectURI())

	err = m.delAuthorizationCode(ctx, code)
	if err != nil {
		return nil, err
	}
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
		// fmt.Println("manager.go - GenerateAccessToken cli.GetDomain: ", cli.GetDomain())
		// fmt.Println("manager.go - GenerateAccessToken tgr.RedirectURI: ", tgr.RedirectURI)
		if err := m.validateURI(cli.GetDomain(), tgr.RedirectURI); err != nil {
			return nil, err
		}
	}

	// fmt.Println("manager.go - GenerateAccessToken - 1")

	if gt == oauth2.ClientCredentials && cli.IsPublic() == true {
		return nil, errors.ErrInvalidClient
	}
	// fmt.Println("manager.go - GenerateAccessToken - 11")

	if gt == oauth2.AuthorizationCode {
		// fmt.Println("manager.go - GenerateAccessToken - 111")
		ti, err := m.getAndDelAuthorizationCode(ctx, tgr)
		if err != nil {
			return nil, err
		}

		// fmt.Println("manager.go - GenerateAccessToken - 2")

		if err := m.validateCodeChallenge(ti, tgr.CodeVerifier); err != nil {
			return nil, err
		}

		// fmt.Println("manager.go - GenerateAccessToken - 3")

		tgr.UserID = ti.GetUserID()
		tgr.Scope = ti.GetScope()
		if exp := ti.GetAccessExpiresIn(); exp > 0 {
			tgr.AccessTokenExp = exp
		}
	}

	// fmt.Println("manager.go - GenerateAccessToken - see tgr.Request.............: ", tgr.Request)

	ti := models.NewToken()
	ti.SetClientID(tgr.ClientID)
	ti.SetUserID(tgr.UserID)
	ti.SetRedirectURI(tgr.RedirectURI)
	ti.SetScope(tgr.Scope)
	ti.SetRole(tgr.Role)

	createAt := time.Now()
	ti.SetAccessCreateAt(createAt)

	// fmt.Println("manager.go - GenerateAccessToken - see ti.............: ", ti)

	// set access token expires
	// NOTE NOTE
	gcfg := m.grantConfig(gt, ti.GetRole())
	aexp := gcfg.AccessTokenExp
	if exp := tgr.AccessTokenExp; exp > 0 {
		// NOTE the refreshToken 3 lines below
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
	if err != nil {
		return nil, err
	}
	ti.SetAccess(av)

	if rv != "" {
		ti.SetRefresh(rv)
	}

	err = m.tokenStore.Create(ctx, ti)
	if err != nil {
		return nil, err
	}

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

// RemoveAllTokensByAccessToken use the access token to delete all tokens
func (m *Manager) RemoveAllTokensByAccessToken(ctx context.Context, access string) error {
	if access == "" {
		return errors.ErrInvalidAccessToken
	}
	return m.tokenStore.RemoveAllTokensByAccess(ctx, access)
}

// RemoveAllTokensByRefreshToken use the refresh token to delete all tokens
func (m *Manager) RemoveAllTokensByRefreshToken(ctx context.Context, refresh string) error {
	if refresh == "" {
		return errors.ErrInvalidAccessToken
	}
	return m.tokenStore.RemoveAllTokensByRefresh(ctx, refresh)
}

// LoadAccessToken according to the access token for corresponding token information
func (m *Manager) LoadAccessToken(ctx context.Context, access string) (oauth2.TokenInfo, error) {
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
