package server

import (
	"context"
	"encoding/json"
	"strconv"

	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	oauth2 "github.com/djedjethai/go-oauth2-openid"
	"github.com/djedjethai/go-oauth2-openid/errors"
)

// NewDefaultServer create a default authorization server
func NewDefaultServer(manager oauth2.Manager) *Server {
	return NewServer(NewConfig(), manager)
}

// NewServer create authorization server
func NewServer(cfg *Config, manager oauth2.Manager) *Server {
	srv := &Server{
		Config:    cfg,
		Manager:   manager,
		IsModeAPI: false,
	}

	// default handler
	srv.ClientInfoHandler = ClientBasicHandler

	srv.UserAuthorizationHandler = func(w http.ResponseWriter, r *http.Request) (string, error) {
		return "", errors.ErrAccessDenied
	}

	srv.PasswordAuthorizationHandler = func(ctx context.Context, clientID, username, password string) (string, error) {
		return "", errors.ErrAccessDenied
	}

	srv.UserOpenidHandler = func(w http.ResponseWriter, r *http.Request, role ...string) (map[string]interface{}, string, string, string, error) {
		return make(map[string]interface{}), "key", "secretKey", "HS256", errors.ErrAccessDenied
	}

	srv.CustomizeTokenPayloadHandler = func(r *http.Request, data map[string]interface{}) (error, interface{}) {
		return nil, data
	}

	return srv
}

// Server Provide authorization server
type Server struct {
	Config                       *Config
	Manager                      oauth2.Manager
	ClientInfoHandler            ClientInfoHandler
	ClientAuthorizedHandler      ClientAuthorizedHandler
	ClientScopeHandler           ClientScopeHandler
	UserAuthorizationHandler     UserAuthorizationHandler
	PasswordAuthorizationHandler PasswordAuthorizationHandler
	RefreshingValidationHandler  RefreshingValidationHandler
	PreRedirectErrorHandler      PreRedirectErrorHandler
	RefreshingScopeHandler       RefreshingScopeHandler
	ResponseErrorHandler         ResponseErrorHandler
	InternalErrorHandler         InternalErrorHandler
	ExtensionFieldsHandler       ExtensionFieldsHandler
	AccessTokenExpHandler        AccessTokenExpHandler
	AuthorizeScopeHandler        AuthorizeScopeHandler
	ResponseTokenHandler         ResponseTokenHandler
	IsModeAPI                    bool
	UserOpenidHandler            UserOpenidHandler
	CustomizeTokenPayloadHandler CustomizeTokenPayloadHandler
}

func (s *Server) handleError(w http.ResponseWriter, req *AuthorizeRequest, err error) error {
	if fn := s.PreRedirectErrorHandler; fn != nil {
		return fn(w, req, err)
	}

	return s.redirectError(w, req, err)
}

// BaseError is a customized error matching the CustomizedError
type BaseError struct {
	Code        int    `json:"code"`
	Description string `json:"description"`
}

// handleCustomizedError handles the Customized errors from the app
func (s *Server) handleCustomizedError(w http.ResponseWriter, req *AuthorizeRequest, err error) error {
	// default error
	errorCode := http.StatusInternalServerError
	ce := BaseError{}
	ce.Code = errorCode
	ce.Description = "internal server error"

	parts := strings.Split(err.Error(), ":")
	if len(parts) == 0 {
		json.NewEncoder(w).Encode(ce)
		return nil
	}

	errorCode, err = strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil {
		json.NewEncoder(w).Encode(ce)
		return nil
	}

	ce.Code = errorCode
	ce.Description = strings.TrimSpace(parts[1])

	w.WriteHeader(errorCode)
	json.NewEncoder(w).Encode(ce)

	return nil
}

func (s *Server) redirectError(w http.ResponseWriter, req *AuthorizeRequest, err error) error {
	if req == nil {
		return err
	}

	data, _, _ := s.GetErrorData(err)

	return s.redirect(w, req, data)
}

func (s *Server) redirect(w http.ResponseWriter, req *AuthorizeRequest, data map[string]interface{}) error {
	if !s.IsModeAPI {
		uri, err := s.GetRedirectURI(req, data)
		if err != nil {
			return err
		}

		w.Header().Set("Location", uri)
		w.WriteHeader(302)
		return nil

	} else {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")

		w.WriteHeader(http.StatusOK)
		return json.NewEncoder(w).Encode(data)
	}
}

func (s *Server) tokenError(w http.ResponseWriter, r *http.Request, ti oauth2.TokenInfo, err error) error {
	data, statusCode, header := s.GetErrorData(err)

	return s.token(w, r, data, header, ti, statusCode)
}

func (s *Server) token(w http.ResponseWriter, r *http.Request, data map[string]interface{}, header http.Header, ti oauth2.TokenInfo, statusCode ...int) error {
	if fn := s.ResponseTokenHandler; fn != nil {
		return fn(w, data, header, statusCode...)
	}

	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	for key := range header {
		w.Header().Set(key, header.Get(key))
	}

	status := http.StatusOK
	if len(statusCode) > 0 && statusCode[0] > 0 {
		status = statusCode[0]
	}

	if status >= 400 {
		w.WriteHeader(status)
		return json.NewEncoder(w).Encode(data["error"].(string))
	}

	// add accessToken and refreshToken to the data, for the user to do what he need
	if ti != nil {
		data["access_token"] = ti.GetAccess()
		data["refresh_token"] = ti.GetRefresh()
	}

	// user can finally cutomize the payload
	// NOTE the err returned should implement the marshaler interface
	err, pl := s.CustomizeTokenPayloadHandler(r, data)
	if err != nil {
		w.WriteHeader(http.StatusOK)
		return json.NewEncoder(w).Encode(err)
	}

	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(pl)
}

// SetModeAPI allow the token to be return within the ResponseWriter instead of being redirected
func (s *Server) SetModeAPI() {
	s.IsModeAPI = true
}

// GetRedirectURI get redirect uri
func (s *Server) GetRedirectURI(req *AuthorizeRequest, data map[string]interface{}) (string, error) {
	u, err := url.Parse(req.RedirectURI)
	if err != nil {
		return "", err
	}

	q := u.Query()
	if req.State != "" {
		q.Set("state", req.State)
	}

	for k, v := range data {
		q.Set(k, fmt.Sprint(v))
	}

	switch req.ResponseType {
	case oauth2.Code:
		u.RawQuery = q.Encode()
	case oauth2.Token:
		u.RawQuery = ""
		fragment, err := url.QueryUnescape(q.Encode())
		if err != nil {
			return "", err
		}
		u.Fragment = fragment
	}

	return u.String(), nil
}

// CheckResponseType check allows response type
func (s *Server) CheckResponseType(rt oauth2.ResponseType) bool {
	for _, art := range s.Config.AllowedResponseTypes {
		if art == rt {
			return true
		}
	}
	return false
}

// CheckCodeChallengeMethod checks for allowed code challenge method
func (s *Server) CheckCodeChallengeMethod(ccm oauth2.CodeChallengeMethod) bool {
	for _, c := range s.Config.AllowedCodeChallengeMethods {
		if c == ccm {
			return true
		}
	}
	return false
}

// ValidationAuthorizeRequest the authorization request validation
func (s *Server) ValidationAuthorizeRequest(r *http.Request) (*AuthorizeRequest, error) {

	redirectURI := r.FormValue("redirect_uri")
	clientID := r.FormValue("client_id")
	if !(r.Method == "GET" || r.Method == "POST") || clientID == "" {
		return nil, errors.ErrInvalidRequest
	}

	resType := oauth2.ResponseType(r.FormValue("response_type"))
	if resType.String() == "" {
		return nil, errors.ErrUnsupportedResponseType
	} else if allowed := s.CheckResponseType(resType); !allowed {
		return nil, errors.ErrUnauthorizedClient
	}

	cc := r.FormValue("code_challenge")
	if cc == "" && s.Config.ForcePKCE {
		return nil, errors.ErrCodeChallengeRquired
	}
	if cc != "" && (len(cc) < 43 || len(cc) > 128) {
		return nil, errors.ErrInvalidCodeChallengeLen
	}

	ccm := oauth2.CodeChallengeMethod(r.FormValue("code_challenge_method"))
	// set default
	if ccm == "" {
		ccm = oauth2.CodeChallengePlain
	}
	if ccm != "" && !s.CheckCodeChallengeMethod(ccm) {
		return nil, errors.ErrUnsupportedCodeChallengeMethod
	}

	req := &AuthorizeRequest{
		RedirectURI:         redirectURI,
		ResponseType:        resType,
		ClientID:            clientID,
		State:               r.FormValue("state"),
		Scope:               r.FormValue("scope"),
		Role:                r.FormValue("role"),
		Request:             r,
		CodeChallenge:       cc,
		CodeChallengeMethod: ccm,
	}
	return req, nil
}

// GetAuthorizeToken get authorization token(code)
func (s *Server) GetAuthorizeToken(ctx context.Context, req *AuthorizeRequest) (oauth2.TokenInfo, error) {

	// check the client allows the grant type
	if fn := s.ClientAuthorizedHandler; fn != nil {

		gt := oauth2.AuthorizationCode
		if req.ResponseType == oauth2.Token {
			gt = oauth2.Implicit
		}

		allowed, err := fn(req.ClientID, gt)
		if err != nil {
			return nil, err
		} else if !allowed {
			return nil, errors.ErrUnauthorizedClient
		}
	}

	tgr := &oauth2.TokenGenerateRequest{
		ClientID:       req.ClientID,
		UserID:         req.UserID,
		RedirectURI:    req.RedirectURI,
		Scope:          req.Scope,
		Role:           req.Role,
		AccessTokenExp: req.AccessTokenExp,
		Request:        req.Request,
	}

	// check the client allows the authorized scope
	if fn := s.ClientScopeHandler; fn != nil {

		allowed, err := fn(tgr)
		if err != nil {
			return nil, err
		} else if !allowed {
			return nil, errors.ErrInvalidScope
		}
	}

	tgr.CodeChallenge = req.CodeChallenge
	tgr.CodeChallengeMethod = req.CodeChallengeMethod

	ti, err := s.Manager.GenerateAuthToken(ctx, req.ResponseType, tgr)

	// fmt.Println("server - server.go - GetAuthorizeToken() - see ti: ", ti, " see err: ", err)

	return ti, err
}

// GetAuthorizeData get authorization response data
func (s *Server) GetAuthorizeData(rt oauth2.ResponseType, ti oauth2.TokenInfo) map[string]interface{} {
	if rt == oauth2.Code {
		return map[string]interface{}{
			"code": ti.GetCode(),
		}
	}
	return s.GetTokenData(ti)
}

// HandleAuthorizeRequest the authorization request handling
func (s *Server) HandleAuthorizeRequest(w http.ResponseWriter, r *http.Request) error {

	ctx := r.Context()

	req, err := s.ValidationAuthorizeRequest(r)
	if err != nil {
		return s.handleError(w, req, err)
	}

	userID, err := s.UserAuthorizationHandler(w, r)
	if err != nil {
		return s.handleCustomizedError(w, req, err)
	} else if userID == "" {
		return nil
	}

	req.UserID = userID

	// specify the scope of authorization
	if fn := s.AuthorizeScopeHandler; fn != nil {
		scope, err := fn(w, r)
		if err != nil {
			return err
		} else if scope != "" {
			req.Scope = scope
		}
	}

	// specify the expiration time of access token
	if fn := s.AccessTokenExpHandler; fn != nil {
		exp, err := fn(w, r)
		if err != nil {
			return err
		}
		req.AccessTokenExp = exp
	}

	ti, err := s.GetAuthorizeToken(ctx, req)
	if err != nil {
		return s.handleError(w, req, err)
	}

	// If the redirect URI is empty, the default domain provided by the client is used.
	if req.RedirectURI == "" {
		client, err := s.Manager.GetClient(ctx, req.ClientID)
		if err != nil {
			return err
		}
		req.RedirectURI = client.GetDomain()
	}

	return s.redirect(w, req, s.GetAuthorizeData(req.ResponseType, ti))
}

// ValidationTokenRequest the token request validation
func (s *Server) ValidationTokenRequest(r *http.Request) (oauth2.GrantType, *oauth2.TokenGenerateRequest, error) {
	if v := r.Method; !(v == "POST" ||
		(s.Config.AllowGetAccessRequest && v == "GET")) {
		return "", nil, errors.ErrInvalidRequest
	}

	gt := oauth2.GrantType(r.FormValue("grant_type"))
	if gt.String() == "" {
		return "", nil, errors.ErrUnsupportedGrantType
	}

	clientID, clientSecret, err := s.ClientInfoHandler(r)
	if err != nil {
		return "", nil, err
	}

	tgr := &oauth2.TokenGenerateRequest{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Request:      r,
	}

	switch gt {
	case oauth2.AuthorizationCode:
		// NOTE NOTE set optional query params
		ru := r.FormValue("token_expiration")
		if len(ru) > 0 {
			rui, err := strconv.Atoi(ru)
			if err == nil {
				tgr.AccessTokenExp = time.Duration(rui) * time.Minute
			}
		}

		role := r.FormValue("role")
		if len(role) > 0 {
			tgr.Role = role
		}

		tgr.RedirectURI = r.FormValue("redirect_uri")
		tgr.Code = r.FormValue("code")
		if tgr.RedirectURI == "" ||
			tgr.Code == "" {
			return "", nil, errors.ErrInvalidRequest
		}
		tgr.CodeVerifier = r.FormValue("code_verifier")
		if s.Config.ForcePKCE && tgr.CodeVerifier == "" {
			return "", nil, errors.ErrInvalidRequest
		}

	case oauth2.PasswordCredentials:
		tgr.Scope = r.FormValue("scope")
		username, password := r.FormValue("username"), r.FormValue("password")
		if username == "" || password == "" {
			return "", nil, errors.ErrInvalidRequest
		}

		userID, err := s.PasswordAuthorizationHandler(r.Context(), clientID, username, password)
		if err != nil {
			return "", nil, err
		} else if userID == "" {
			return "", nil, errors.ErrInvalidGrant
		}
		tgr.UserID = userID
	case oauth2.ClientCredentials:
		tgr.Scope = r.FormValue("scope")
	case oauth2.Refreshing:
		tgr.Refresh = r.FormValue("refresh_token")
		tgr.Scope = r.FormValue("scope")
		if tgr.Refresh == "" {
			return "", nil, errors.ErrInvalidRequest
		}
	}

	return gt, tgr, nil
}

// CheckGrantType check allows grant type
func (s *Server) CheckGrantType(gt oauth2.GrantType) bool {
	for _, agt := range s.Config.AllowedGrantTypes {
		if agt == gt {
			return true
		}
	}
	return false
}

// GetAccessToken access token
func (s *Server) GetAccessToken(ctx context.Context, gt oauth2.GrantType, tgr *oauth2.TokenGenerateRequest) (oauth2.TokenInfo, error) {

	if allowed := s.CheckGrantType(gt); !allowed {
		return nil, errors.ErrUnauthorizedClient
	}

	if fn := s.ClientAuthorizedHandler; fn != nil {
		allowed, err := fn(tgr.ClientID, gt)
		if err != nil {
			return nil, err
		} else if !allowed {
			return nil, errors.ErrUnauthorizedClient
		}
	}

	switch gt {
	case oauth2.AuthorizationCode:
		ti, err := s.Manager.GenerateAccessToken(ctx, gt, tgr)
		if err != nil {

			switch err {
			case errors.ErrInvalidAuthorizeCode, errors.ErrInvalidCodeChallenge, errors.ErrMissingCodeChallenge:
				return nil, errors.ErrInvalidGrant
			case errors.ErrInvalidClient:
				return nil, errors.ErrInvalidClient
			default:
				return nil, err
			}
		}

		return ti, nil
	case oauth2.PasswordCredentials, oauth2.ClientCredentials:
		if fn := s.ClientScopeHandler; fn != nil {
			allowed, err := fn(tgr)
			if err != nil {
				return nil, err
			} else if !allowed {
				return nil, errors.ErrInvalidScope
			}
		}
		return s.Manager.GenerateAccessToken(ctx, gt, tgr)
	case oauth2.Refreshing:
		// check scope
		if scopeFn := s.RefreshingScopeHandler; tgr.Scope != "" && scopeFn != nil {
			rti, err := s.Manager.LoadRefreshToken(ctx, tgr.Refresh)
			if err != nil {
				if err == errors.ErrInvalidRefreshToken || err == errors.ErrExpiredRefreshToken {
					return nil, errors.ErrInvalidGrant
				}
				return nil, err
			}

			allowed, err := scopeFn(tgr, rti.GetScope())
			if err != nil {
				return nil, err
			} else if !allowed {
				return nil, errors.ErrInvalidScope
			}
		}

		if validationFn := s.RefreshingValidationHandler; validationFn != nil {
			rti, err := s.Manager.LoadRefreshToken(ctx, tgr.Refresh)
			if err != nil {
				if err == errors.ErrInvalidRefreshToken || err == errors.ErrExpiredRefreshToken {
					return nil, errors.ErrInvalidGrant
				}
				return nil, err
			}
			allowed, err := validationFn(rti)
			if err != nil {
				return nil, err
			} else if !allowed {
				return nil, errors.ErrInvalidScope
			}
		}

		ti, err := s.Manager.RefreshAccessToken(ctx, tgr)
		if err != nil {
			if err == errors.ErrInvalidRefreshToken || err == errors.ErrExpiredRefreshToken {
				return nil, errors.ErrInvalidGrant
			}
			return nil, err
		}

		return ti, nil
	}

	return nil, errors.ErrUnsupportedGrantType
}

// GetTokenData token data
func (s *Server) GetTokenData(ti oauth2.TokenInfo) map[string]interface{} {
	data := map[string]interface{}{
		"access_token": ti.GetAccess(),
		"token_type":   s.Config.TokenType,
		"expires_in":   int64(ti.GetAccessExpiresIn() / time.Second),
	}

	if scope := ti.GetScope(); scope != "" {
		data["scope"] = scope
	}

	if refresh := ti.GetRefresh(); refresh != "" {
		data["refresh_token"] = refresh
	}

	if fn := s.ExtensionFieldsHandler; fn != nil {
		ext := fn(ti)
		for k, v := range ext {
			if _, ok := data[k]; ok {
				continue
			}
			data[k] = v
		}
	}
	return data
}

// GetTokenData token data
func (s *Server) GetJWTokenData(ti oauth2.TokenInfo, jwtToken, jwtRefreshToken string, data map[string]interface{}) map[string]interface{} {
	data["jwt_access_token"] = jwtToken
	data["token_type"] = s.Config.TokenType
	data["expires_in"] = int64(ti.GetAccessExpiresIn() / time.Second)

	data["jwt_refresh_token"] = jwtRefreshToken

	data["role"] = ti.GetRole()

	// if fn := s.ExtensionFieldsHandler; fn != nil {
	// 	ext := fn(ti)
	// 	for k, v := range ext {
	// 		if _, ok := data[k]; ok {
	// 			continue
	// 		}
	// 		data[k] = v
	// 	}
	// }
	return data
}

// HandleOpenidRequest handle the creation of the jwtokens and return them
func (s *Server) HandleOpenidRequest(ctx context.Context, w http.ResponseWriter, r *http.Request, ti oauth2.TokenInfo) (map[string]interface{}, error) {

	// in UserOpenidHandler a call to the db can be done to populate the user info
	data, keyID, secretKey, encoding, err := s.UserOpenidHandler(w, r, ti.GetRole())
	if err != nil {
		return nil, err
	}

	// overwrite the role allow to finally customumize it
	if role := r.FormValue("role"); len(role) > 0 {
		ti.SetRole(role)
	}

	// role must be set
	role := ti.GetRole()
	if role == "" {
		return nil, errors.New("no role defined")
	}

	jwtAG := s.Manager.CreateJWTAccessGenerate(keyID, []byte(secretKey), encoding)
	at, rt, err := jwtAG.GenerateOpenidJWToken(ctx, ti, true, oauth2.OpenidInfo(data))
	if err != nil {
		return nil, errors.ErrServerError
	}

	return s.GetJWTokenData(ti, at, rt, data), nil
}

func (s *Server) HandleJWTokenValidation(ctx context.Context, r *http.Request, jwt, keyID, secretKey, encoding string) error {

	jwtAG := s.Manager.CreateJWTAccessGenerate(keyID, []byte(secretKey), encoding)

	return jwtAG.ValidOpenidJWToken(ctx, jwt)
}

func (s *Server) HandleJWTokenGetdata(ctx context.Context, r *http.Request, jwt, keyID, secretKey, encoding string) (map[string]interface{}, error) {

	jwtAG := s.Manager.CreateJWTAccessGenerate(keyID, []byte(secretKey), encoding)

	return jwtAG.GetdataOpenidJWToken(ctx, jwt)
}

// HandleJWTokenAdminGetdata return the jwt data, the jwt expiration does not matter
func (s *Server) HandleJWTokenAdminGetdata(ctx context.Context, r *http.Request, jwt, keyID, secretKey, encoding string) (map[string]interface{}, error) {

	jwtAG := s.Manager.CreateJWTAccessGenerate(keyID, []byte(secretKey), encoding)

	return jwtAG.GetdataAdminOpenidJWToken(ctx, jwt)
}

// UpsertJWTokenClient upsert JWToken matching the client APIserver
func (s *Server) UpsertClientJWToken(ctx context.Context, id, JWToken string) error {
	return s.Manager.UpsertClientJWToken(ctx, id, JWToken)
}

// RefreshOpenidToken valid and refresh(if not expire) the jwtokens
func (s *Server) RefreshOpenidToken(ctx context.Context, w http.ResponseWriter, r *http.Request, data map[string]interface{}) error {
	_, keyID, secretKey, encoding, err := s.UserOpenidHandler(w, r)
	if err != nil {
		return err
	}

	jwtAG := s.Manager.CreateJWTAccessGenerate(keyID, []byte(secretKey), encoding)

	accessJWToken := r.Header.Get("jwt_access_token")
	refreshJWToken := r.Header.Get("jwt_refresh_token")
	refreshToken := r.Header.Get("refresh_token")

	// if accessJWToken is invalid return but if expired continue
	err = jwtAG.ValidOpenidJWToken(ctx, accessJWToken)
	if err != nil && err.Error() == "invalid jwt token" {
		return err
	}

	// if refreshJWToken is invalid return, if expired return
	err = jwtAG.ValidOpenidJWToken(ctx, refreshJWToken)
	if err != nil {
		return err
	} else {

		// get tokenInfo data matching the rt
		ti, err := s.Manager.RefreshTokens(ctx, refreshToken)
		if err != nil {
			return err
		}

		// set the ti created time to now()
		ti.SetAccessCreateAt(time.Now())

		delete(data, "sub")

		atJWT, rtJWT, err := jwtAG.GenerateOpenidJWToken(ctx, ti, true, data)
		if err != nil {
			return errors.ErrServerError
		}

		data["jwt_access_token"] = atJWT
		data["jwt_refresh_token"] = rtJWT

		return s.token(w, r, data, nil, ti, http.StatusOK)
	}

}

// HandleTokenRequest token request handling
func (s *Server) HandleTokenRequest(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()

	gt, tgr, err := s.ValidationTokenRequest(r)
	if err != nil {
		return s.tokenError(w, r, nil, err)
	}

	ti, err := s.GetAccessToken(ctx, gt, tgr)
	if err != nil {
		return s.tokenError(w, r, nil, err)
	}

	//fmt.Println("server.go - HandleTokenRequest - ti: ", ti)
	scopesArray := strings.Split(ti.GetScope(), ",")
	if len(scopesArray) > 0 {
		for _, sc := range scopesArray {
			// case openid is requested
			if strings.TrimSpace(sc) == "openid" {
				data, err := s.HandleOpenidRequest(ctx, w, r, ti)
				if err != nil {
					return s.tokenError(w, r, ti, err)
				}

				return s.token(w, r, data, nil, ti)
			}
		}
	}

	// NOTE in case of token, that should return the tokens
	return s.token(w, r, s.GetTokenData(ti), nil, ti)
}

// GetErrorData get error response data
func (s *Server) GetErrorData(err error) (map[string]interface{}, int, http.Header) {
	var re errors.Response
	if v, ok := errors.Descriptions[err]; ok {
		re.Error = err
		re.Description = v
		re.StatusCode = errors.StatusCodes[err]
	} else {
		if fn := s.InternalErrorHandler; fn != nil {
			if v := fn(err); v != nil {
				re = *v
			}
		}

		if re.Error == nil {
			re.Error = errors.ErrServerError
			re.Description = errors.Descriptions[errors.ErrServerError]
			re.StatusCode = errors.StatusCodes[errors.ErrServerError]
		}
	}

	if fn := s.ResponseErrorHandler; fn != nil {
		fn(&re)
	}

	data := make(map[string]interface{})
	if err := re.Error; err != nil {
		data["error"] = err.Error()
	}

	if v := re.ErrorCode; v != 0 {
		data["error_code"] = v
	}

	if v := re.Description; v != "" {
		data["error_description"] = v
	}

	if v := re.URI; v != "" {
		data["error_uri"] = v
	}

	statusCode := http.StatusInternalServerError
	if v := re.StatusCode; v > 0 {
		statusCode = v
	}

	return data, statusCode, re.Header
}

// BearerAuth parse bearer token
func (s *Server) BearerAuth(r *http.Request) (string, bool) {
	auth := r.Header.Get("Authorization")
	prefix := "Bearer "
	token := ""

	if auth != "" && strings.HasPrefix(auth, prefix) {
		token = auth[len(prefix):]
	} else {
		token = r.FormValue("access_token")
	}

	return token, token != ""
}

// ValidationBearerToken validation the bearer tokens
// https://tools.ietf.org/html/rfc6750
func (s *Server) ValidationBearerToken(r *http.Request) (oauth2.TokenInfo, error) {
	ctx := r.Context()

	accessToken, ok := s.BearerAuth(r)
	if !ok {
		return nil, errors.ErrInvalidAccessToken
	}

	return s.Manager.LoadAccessToken(ctx, accessToken)
}
