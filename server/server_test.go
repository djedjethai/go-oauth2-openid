package server_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	oauth2 "github.com/djedjethai/go-oauth2-openid"
	"github.com/djedjethai/go-oauth2-openid/errors"
	"github.com/djedjethai/go-oauth2-openid/manage"
	"github.com/djedjethai/go-oauth2-openid/models"
	"github.com/djedjethai/go-oauth2-openid/server"
	"github.com/djedjethai/go-oauth2-openid/store"
	"github.com/gavv/httpexpect"
)

var (
	srv          *server.Server
	tsrv         *httptest.Server
	manager      *manage.Manager
	csrv         *httptest.Server
	clientID     = "111111"
	clientSecret = "11111111"

	plainChallenge = "ThisIsAFourtyThreeCharactersLongStringThing"
	s256Challenge  = "s256tests256tests256tests256tests256tests256test"
	// sha2562 := sha256.Sum256([]byte(s256Challenge))
	// fmt.Printf(base64.URLEncoding.EncodeToString(sha2562[:]))
	s256ChallengeHash = "To2Xqv01cm16bC9Sf7KRRS8CO2SFss_HSMQOr3sdCDE="

	// openid
	keyIDDefault     = "key"
	secretKeyDefault = "secretKey"
	keyID            = "theKeyID"
	secretKey        = "mySecretKey"
	encoding         = "HS256"
	jwtAge           = "35"
	jwtName          = "Robert"
	jwtCity          = "London"
	jwtScope         = "read, openid"
	jwtRole          = "user"
	jwtRoleAPIserver = "APIserver"

	jwtAccessToken  string
	jwtRefreshToken string
	refreshToken    string
	codeTestExp     string
)

func init() {
	manager = manage.NewDefaultManager()
	manager.MustTokenStorage(store.NewMemoryTokenStore())
}

func clientStore(domain string, public bool) oauth2.ClientStore {
	clientStore := store.NewClientStore()
	var secret string
	if public {
		secret = ""
	} else {
		secret = clientSecret
	}
	clientStore.Set(clientID, &models.Client{
		ID:     clientID,
		Secret: secret,
		Domain: domain,
		Public: public,
	})
	return clientStore
}

func testServer(t *testing.T, w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/authorize":
		err := srv.HandleAuthorizeRequest(w, r)
		if err != nil {
			t.Error(err)
		}
	case "/token":
		err := srv.HandleTokenRequest(w, r)
		if err != nil {
			t.Error(err)
		}
	}
}

func OpenidService(w http.ResponseWriter, r *http.Request, role ...string) (jwtInfo map[string]interface{}, keyid string, secretkey string, encoding string, err error) {
	keyid = keyIDDefault
	secretkey = secretKeyDefault
	encoding = "HS256"

	jwtInfo = make(map[string]interface{})
	jwtInfo["name"] = "Robert"
	jwtInfo["age"] = "35"
	jwtInfo["city"] = "London"

	err = nil
	return
}

func TestAuthorizeCode(t *testing.T) {
	tsrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		testServer(t, w, r)
	}))
	defer tsrv.Close()

	e := httpexpect.New(t, tsrv.URL)

	csrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth2":
			r.ParseForm()
			code, state := r.Form.Get("code"), r.Form.Get("state")
			if state != "123" {
				t.Error("unrecognized state:", state)
				return
			}
			resObj := e.POST("/token").
				WithFormField("redirect_uri", csrv.URL+"/oauth2").
				WithFormField("code", code).
				WithFormField("grant_type", "authorization_code").
				WithFormField("client_id", clientID).
				WithBasicAuth(clientID, clientSecret).
				Expect().
				Status(http.StatusOK).
				JSON().Object()

			t.Logf("TestAuthorizeCode response: %#v\n", resObj.Raw())

			validationAccessToken(t, resObj.Value("access_token").String().Raw())
		}
	}))
	defer csrv.Close()

	manager.MapClientStorage(clientStore(csrv.URL, true))
	srv = server.NewDefaultServer(manager)
	// set the user authorization handler
	srv.SetUserAuthorizationHandler(func(w http.ResponseWriter, r *http.Request) (userID string, err error) {
		userID = "000000"
		return
	})

	e.GET("/authorize").
		WithQuery("response_type", "code").
		WithQuery("client_id", clientID).
		WithQuery("scope", "all").
		WithQuery("state", "123").
		WithQuery("redirect_uri", csrv.URL+"/oauth2").
		Expect().Status(http.StatusOK)
}

func TestAuthorizeCodeWithChallengePlain(t *testing.T) {
	tsrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		testServer(t, w, r)
	}))
	defer tsrv.Close()

	e := httpexpect.New(t, tsrv.URL)

	csrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth2":
			r.ParseForm()
			code, state := r.Form.Get("code"), r.Form.Get("state")
			if state != "123" {
				t.Error("unrecognized state:", state)
				return
			}
			resObj := e.POST("/token").
				WithFormField("redirect_uri", csrv.URL+"/oauth2").
				WithFormField("code", code).
				WithFormField("grant_type", "authorization_code").
				WithFormField("client_id", clientID).
				WithFormField("code", code).
				WithFormField("code_verifier", plainChallenge).
				Expect().
				Status(http.StatusOK).
				JSON().Object()

			t.Logf("TestAuthorizeCodeWithChallengePlain response: %#v\n", resObj.Raw())

			validationAccessToken(t, resObj.Value("access_token").String().Raw())
		}
	}))
	defer csrv.Close()

	manager.MapClientStorage(clientStore(csrv.URL, true))
	srv = server.NewDefaultServer(manager)
	srv.SetUserAuthorizationHandler(func(w http.ResponseWriter, r *http.Request) (userID string, err error) {
		userID = "000000"
		return
	})

	srv.SetClientInfoHandler(server.ClientFormHandler)

	e.GET("/authorize").
		WithQuery("response_type", "code").
		WithQuery("client_id", clientID).
		WithQuery("scope", "all").
		WithQuery("state", "123").
		WithQuery("redirect_uri", csrv.URL+"/oauth2").
		WithQuery("code_challenge", plainChallenge).
		Expect().Status(http.StatusOK)
}

func TestAuthorizeCodeWithChallengeS256(t *testing.T) {
	tsrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		testServer(t, w, r)
	}))
	defer tsrv.Close()

	e := httpexpect.New(t, tsrv.URL)

	csrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth2":
			r.ParseForm()
			code, state := r.Form.Get("code"), r.Form.Get("state")
			if state != "123" {
				t.Error("unrecognized state:", state)
				return
			}
			resObj := e.POST("/token").
				WithFormField("redirect_uri", csrv.URL+"/oauth2").
				WithFormField("code", code).
				WithFormField("grant_type", "authorization_code").
				WithFormField("client_id", clientID).
				WithFormField("code", code).
				WithFormField("code_verifier", s256Challenge).
				Expect().
				Status(http.StatusOK).
				JSON().Object()

			t.Logf("%#v\n", resObj.Raw())

			validationAccessToken(t, resObj.Value("access_token").String().Raw())
		}
	}))
	defer csrv.Close()

	manager.MapClientStorage(clientStore(csrv.URL, true))
	srv = server.NewDefaultServer(manager)
	srv.SetUserAuthorizationHandler(func(w http.ResponseWriter, r *http.Request) (userID string, err error) {
		userID = "000000"
		return
	})

	srv.SetClientInfoHandler(server.ClientFormHandler)

	e.GET("/authorize").
		WithQuery("response_type", "code").
		WithQuery("client_id", clientID).
		WithQuery("scope", "all").
		WithQuery("state", "123").
		WithQuery("redirect_uri", csrv.URL+"/oauth2").
		WithQuery("code_challenge", s256ChallengeHash).
		WithQuery("code_challenge_method", "S256").
		Expect().Status(http.StatusOK)
}

func TestImplicit(t *testing.T) {
	tsrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		testServer(t, w, r)
	}))
	defer tsrv.Close()
	e := httpexpect.New(t, tsrv.URL)

	csrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer csrv.Close()

	manager.MapClientStorage(clientStore(csrv.URL, false))
	srv = server.NewDefaultServer(manager)
	srv.SetUserAuthorizationHandler(func(w http.ResponseWriter, r *http.Request) (userID string, err error) {
		userID = "000000"
		return
	})

	e.GET("/authorize").
		WithQuery("response_type", "token").
		WithQuery("client_id", clientID).
		WithQuery("scope", "all").
		WithQuery("state", "123").
		WithQuery("redirect_uri", csrv.URL+"/oauth2").
		Expect().Status(http.StatusOK)
}

func TestPasswordCredentials(t *testing.T) {
	tsrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		testServer(t, w, r)
	}))
	defer tsrv.Close()
	e := httpexpect.New(t, tsrv.URL)

	manager.MapClientStorage(clientStore("", false))
	srv = server.NewDefaultServer(manager)
	srv.SetPasswordAuthorizationHandler(func(ctx context.Context, clientID, username, password string) (userID string, err error) {
		if username == "admin" && password == "123456" {
			userID = "000000"
			return
		}
		err = fmt.Errorf("user not found")
		return
	})

	resObj := e.POST("/token").
		WithFormField("grant_type", "password").
		WithFormField("username", "admin").
		WithFormField("password", "123456").
		WithFormField("scope", "all").
		WithBasicAuth(clientID, clientSecret).
		Expect().
		Status(http.StatusOK).
		JSON().Object()

	t.Logf("%#v\n", resObj.Raw())

	validationAccessToken(t, resObj.Value("access_token").String().Raw())
}

func TestClientCredentials(t *testing.T) {
	tsrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		testServer(t, w, r)
	}))
	defer tsrv.Close()
	e := httpexpect.New(t, tsrv.URL)

	manager.MapClientStorage(clientStore("", false))

	srv = server.NewDefaultServer(manager)
	srv.SetClientInfoHandler(server.ClientFormHandler)

	srv.SetInternalErrorHandler(func(err error) (re *errors.Response) {
		t.Log("OAuth 2.0 Error:", err.Error())
		return
	})

	srv.SetResponseErrorHandler(func(re *errors.Response) {
		t.Log("Response Error:", re.Error)
	})

	srv.SetAllowedGrantType(oauth2.ClientCredentials)
	srv.SetAllowGetAccessRequest(false)
	srv.SetExtensionFieldsHandler(func(ti oauth2.TokenInfo) (fieldsValue map[string]interface{}) {
		fieldsValue = map[string]interface{}{
			"extension": "param",
		}
		return
	})
	srv.SetAuthorizeScopeHandler(func(w http.ResponseWriter, r *http.Request) (scope string, err error) {
		return
	})
	srv.SetClientScopeHandler(func(tgr *oauth2.TokenGenerateRequest) (allowed bool, err error) {
		allowed = true
		return
	})

	resObj := e.POST("/token").
		WithFormField("grant_type", "client_credentials").
		WithFormField("scope", "all").
		WithFormField("client_id", clientID).
		WithFormField("client_secret", clientSecret).
		Expect().
		Status(http.StatusOK).
		JSON().Object()

	t.Logf("%#v\n", resObj.Raw())

	validationAccessToken(t, resObj.Value("access_token").String().Raw())
}

func TestRefreshing(t *testing.T) {
	tsrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		testServer(t, w, r)
	}))
	defer tsrv.Close()
	e := httpexpect.New(t, tsrv.URL)

	csrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth2":
			r.ParseForm()
			code, state := r.Form.Get("code"), r.Form.Get("state")
			if state != "123" {
				t.Error("unrecognized state:", state)
				return
			}
			jresObj := e.POST("/token").
				WithFormField("redirect_uri", csrv.URL+"/oauth2").
				WithFormField("code", code).
				WithFormField("grant_type", "authorization_code").
				WithFormField("client_id", clientID).
				WithBasicAuth(clientID, clientSecret).
				Expect().
				Status(http.StatusOK).
				JSON().Object()

			t.Logf("%#v\n", jresObj.Raw())

			validationAccessToken(t, jresObj.Value("access_token").String().Raw())

			resObj := e.POST("/token").
				WithFormField("grant_type", "refresh_token").
				WithFormField("scope", "one").
				WithFormField("refresh_token", jresObj.Value("refresh_token").String().Raw()).
				WithBasicAuth(clientID, clientSecret).
				Expect().
				Status(http.StatusOK).
				JSON().Object()

			t.Logf("%#v\n", resObj.Raw())

			validationAccessToken(t, resObj.Value("access_token").String().Raw())
		}
	}))
	defer csrv.Close()

	manager.MapClientStorage(clientStore(csrv.URL, true))
	srv = server.NewDefaultServer(manager)

	srv.SetUserAuthorizationHandler(func(w http.ResponseWriter, r *http.Request) (userID string, err error) {
		userID = "000000"
		return
	})

	e.GET("/authorize").
		WithQuery("response_type", "code").
		WithQuery("client_id", clientID).
		WithQuery("scope", "all").
		WithQuery("state", "123").
		WithQuery("redirect_uri", csrv.URL+"/oauth2").
		Expect().Status(http.StatusOK)
}

/*
* Test openid
 */
// TestAuthorizeCodeWithChallengeS256OpenidDefault test openid with the default
func TestAuthorizeCodeWithChallengeS256OpenidDefault(t *testing.T) {
	tsrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		testServer(t, w, r)
	}))
	defer tsrv.Close()

	e := httpexpect.New(t, tsrv.URL)

	csrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth2":
		}
	}))
	defer csrv.Close()

	manager.MapClientStorage(clientStore(csrv.URL, true))
	srv = server.NewDefaultServer(manager)

	srv.SetModeAPI()

	srv.SetUserAuthorizationHandler(func(w http.ResponseWriter, r *http.Request) (userID string, err error) {
		userID = "000000"
		return
	})

	srv.SetClientInfoHandler(server.ClientFormHandler)

	resObj := e.GET("/authorize").
		WithQuery("response_type", "code").
		WithQuery("client_id", clientID).
		WithQuery("role", jwtRoleAPIserver).
		WithQuery("scope", "read, openid").
		WithQuery("state", "123").
		WithQuery("redirect_uri", csrv.URL+"/oauth2").
		WithQuery("code_challenge", s256ChallengeHash).
		WithQuery("code_challenge_method", "S256").
		Expect().Status(http.StatusOK)

	jsonBody := resObj.Body().Raw()

	jsonBody = strings.TrimSpace(jsonBody)

	// Decode the JSON string
	var responseData map[string]interface{}
	if err := json.Unmarshal([]byte(jsonBody), &responseData); err != nil {
		fmt.Println("error unmarshal the err: ", err)
	}

	code, ok := responseData["code"].(string)
	if !ok {
		fmt.Println("Failed to extract 'code' from JSON")
	}

	srv.SetUserOpenidHandler(OpenidService)

	resObj1 := e.POST("/token").
		WithFormField("redirect_uri", csrv.URL+"/oauth2").
		WithFormField("code", code).
		WithQuery("role", jwtRoleAPIserver).
		WithFormField("token_expiration", 1). // set the token validity to 1mn
		WithFormField("grant_type", "authorization_code").
		WithFormField("client_id", clientID).
		WithFormField("code_verifier", s256Challenge).
		Expect().
		Status(http.StatusOK).
		JSON().Object()

	responseData = resObj1.Raw()

	accessJWTexpiresIn, ok := responseData["expires_in"]
	if !ok {
		t.Error("Failed to extract 'expires_in' from the response")
	}

	// Extract the jwt_refresh_token and jwt_access_token
	jwtRefreshToken, ok = responseData["jwt_refresh_token"].(string)
	if !ok {
		t.Error("Failed to extract 'jwt_refresh_token' from the response")
	}

	jwtAccessToken, ok = responseData["jwt_access_token"].(string)
	if !ok {
		t.Error("Failed to extract 'jwt_access_token' from the response")
	}

	// assert jwtAccessToken duration, here set to 60s
	if accessJWTexpiresIn != float64(60) {
		t.Error("invalid jwt_access_token duration")
	}

	t.Logf("%#v\n", jwtAccessToken)
	t.Logf("%#v\n", jwtRefreshToken)
}

func TestDefaultJWTokensValidity(t *testing.T) {

	r := &http.Request{}
	err := srv.HandleJWTokenValidation(context.TODO(), r, jwtAccessToken, keyIDDefault, secretKeyDefault, encoding)
	if err != nil {
		t.Error("error invalid jwt")
	}

	err = srv.HandleJWTokenValidation(context.TODO(), r, jwtRefreshToken, keyIDDefault, secretKeyDefault, encoding)
	if err != nil {
		t.Error("error invalid jwt")
	}

	// with invalid key
	err = srv.HandleJWTokenValidation(context.TODO(), r, jwtRefreshToken, keyIDDefault, "invalidSecretKey", encoding)
	if err == nil {
		t.Error("jwt should be invalid")
	}
	if err.Error() != "invalid jwt token" {
		t.Error("jwt should be invalid")
	}
}

// registering the CustomUserOpenidHandler()
func TestAuthorizeCodeWithChallengeS256OpenidCustomUserOpenidHandler(t *testing.T) {
	tsrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		testServer(t, w, r)
	}))
	defer tsrv.Close()

	e := httpexpect.New(t, tsrv.URL)

	csrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth2":
			// case "/jwtgetdata":

		}
	}))
	defer csrv.Close()

	manager.MapClientStorage(clientStore(csrv.URL, true))
	srv = server.NewDefaultServer(manager)

	srv.SetModeAPI()

	srv.SetUserAuthorizationHandler(func(w http.ResponseWriter, r *http.Request) (userID string, err error) {
		userID = "000000"
		return
	})

	srv.SetCustomizeTokenPayloadHandler(func(r *http.Request, data map[string]interface{}) (error, interface{}) {
		var ok bool
		refreshToken, ok = data["refresh_token"].(string)
		if !ok {
			t.Error("Failed to extract 'refresh_token' from CustomizeTokenPayloadHandler")
		}

		return nil, data
	})

	srv.SetClientInfoHandler(server.ClientFormHandler)

	// custom the jwt set the 'key', 'secretKey', encoding, error
	// got user's data from the http.Request
	// key and secretKey can be specific to role
	srv.SetUserOpenidHandler(func(w http.ResponseWriter, r *http.Request, role ...string) (map[string]interface{}, string, string, string, error) {
		var err error = nil

		jwtInfo := make(map[string]interface{})
		jwtInfo["name"] = jwtName
		jwtInfo["age"] = jwtAge
		jwtInfo["city"] = jwtCity
		// jwtInfo["role"] = jwtRole

		return jwtInfo, keyID, secretKey, encoding, err
	})

	resObj := e.GET("/authorize").
		WithQuery("response_type", "code").
		WithQuery("client_id", clientID).
		WithQuery("scope", "read, openid").
		WithQuery("state", "123").
		WithQuery("redirect_uri", csrv.URL+"/oauth2").
		WithQuery("code_challenge", s256ChallengeHash).
		WithQuery("code_challenge_method", "S256").
		Expect().Status(http.StatusOK)

	jsonBody := resObj.Body().Raw()

	jsonBody = strings.TrimSpace(jsonBody)

	// Decode the JSON string
	var responseData map[string]interface{}
	if err := json.Unmarshal([]byte(jsonBody), &responseData); err != nil {
		fmt.Println("error unmarshal the err: ", err)
	}

	code, ok := responseData["code"].(string)
	if !ok {
		fmt.Println("Failed to extract 'code' from JSON")
	}

	// NOTE that the role is optional or can also be add in SetUserOpenidHandler()
	resObj1 := e.POST("/token").
		WithFormField("redirect_uri", csrv.URL+"/oauth2").
		WithFormField("code", code).
		WithFormField("role", jwtRole).
		WithFormField("grant_type", "authorization_code").
		WithFormField("client_id", clientID).
		WithFormField("code_verifier", s256Challenge).
		Expect().
		Status(http.StatusOK).
		JSON().Object()

	responseData = resObj1.Raw()

	accessJWTexpiresIn, ok := responseData["expires_in"]
	if !ok {
		t.Error("Failed to extract 'expires_in' from the response")
	}

	// Extract the jwt_refresh_token and jwt_access_token
	jwtRefreshToken, ok = responseData["jwt_refresh_token"].(string)
	if !ok {
		t.Error("Failed to extract 'jwt_refresh_token' from the response")
	}

	jwtAccessToken, ok = responseData["jwt_access_token"].(string)
	if !ok {
		t.Error("Failed to extract 'jwt_access_token' from the response")
	}

	// assert jwtAccessToken duration, by default it's set to 2hours
	if accessJWTexpiresIn != float64(7200) {
		t.Error("invalid jwt_access_token duration")
	}

	t.Logf("%#v\n", jwtAccessToken)
	t.Logf("%#v\n", jwtRefreshToken)
}

func TestCustomizedJWTokensValidity(t *testing.T) {
	r := &http.Request{}
	err := srv.HandleJWTokenValidation(context.TODO(), r, jwtAccessToken, keyID, secretKey, encoding)
	if err != nil {
		t.Error("error invalid jwt")
	}

	err = srv.HandleJWTokenValidation(context.TODO(), r, jwtRefreshToken, keyID, secretKey, encoding)
	if err != nil {
		t.Error("error invalid jwt")
	}

	// with invalid key
	err = srv.HandleJWTokenValidation(context.TODO(), r, jwtRefreshToken, keyID, "invalidSecretKey", encoding)
	if err == nil {
		t.Error("jwt should be invalid")
	}
	if err.Error() != "invalid jwt token" {
		t.Error("jwt should be invalid")
	}
}

func TestJWTokensData(t *testing.T) {
	// test jwtAccessToken data
	r := &http.Request{}
	data, err := srv.HandleJWTokenGetdata(context.TODO(), r, jwtAccessToken, keyID, secretKey, encoding)
	if err != nil {
		fmt.Println("error getting data from jwt")
	}

	if data["age"] != jwtAge {
		t.Error("jwt own invalid age")
	}
	if data["name"] != jwtName {
		t.Error("jwt own invalid name")
	}
	if data["city"] != jwtCity {
		t.Error("jwt own invalid city")
	}
	if data["scope"] != jwtScope {
		t.Error("jwt own invalid scope")
	}
	if data["role"] != jwtRole {
		t.Error("jwt own invalid role")
	}

	data, err = srv.HandleJWTokenGetdata(context.TODO(), r, jwtRefreshToken, keyID, secretKey, encoding)
	if err != nil {
		fmt.Println("error getting data from jwt")
	}

	if data["age"] != jwtAge {
		t.Error("jwt own invalid age")
	}
	if data["name"] != jwtName {
		t.Error("jwt own invalid name")
	}
	if data["city"] != jwtCity {
		t.Error("jwt own invalid city")
	}
	if data["scope"] != jwtScope {
		t.Error("jwt own invalid scope")
	}
	if data["role"] != jwtRole {
		t.Error("jwt own invalid role")
	}
}

func TestRefreshJWT(t *testing.T) {
	// Create a new request with the refresh_token header
	req, err := http.NewRequest("GET", "http://example.com", nil)
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}

	datas := make(map[string]interface{})
	datas["name"] = "rob"
	datas["age"] = 34

	// set the request
	req.Header.Set("refresh_token", refreshToken)
	req.Header.Set("jwt_refresh_token", jwtRefreshToken)
	req.Header.Set("jwt_access_token", jwtAccessToken)

	handler := func(w http.ResponseWriter, r *http.Request) {
		err := srv.RefreshOpenidToken(context.TODO(), w, r, datas)
		if err != nil {
			fmt.Println("error from refresh openid token")
		}
	}

	recorder := httptest.NewRecorder()

	handler(recorder, req)

	var dataN map[string]interface{}
	err = json.NewDecoder(recorder.Body).Decode(&dataN)
	if err != nil {
		fmt.Println("Error decoding JSON:", err)
		return
	}

	fmt.Println("sse tdataN: ", dataN)

	name, ok := dataN["name"]
	if !ok && name != "rob" {
		t.Error("Failed to extract 'name' from the response")
	}

	age, ok := dataN["age"]
	if !ok && age != "34" {
		t.Error("Failed to extract 'name' from the response")
	}

	// Extract the jwt_refresh_token and jwt_access_token
	jwtRefreshTokenRefreshed, ok := dataN["jwt_refresh_token"].(string)
	if !ok {
		t.Error("Failed to extract 'jwt_refresh_token' from the response")
	}

	jwtAccessTokenRefreshed, ok := dataN["jwt_access_token"].(string)
	if !ok {
		t.Error("Failed to extract 'jwt_access_token' from the response")
	}

	if jwtAccessToken == jwtAccessTokenRefreshed {
		t.Error("jwtAccessToken as not been refreshed")
	}

	if jwtRefreshToken == jwtRefreshTokenRefreshed {
		t.Error("jwtRefreshToken as not been refreshed")
	}
}

func TestAuthorizeCodeWithChallengeS256OpenidDefaultForAPIServer(t *testing.T) {
	tsrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		testServer(t, w, r)
	}))
	defer tsrv.Close()

	e := httpexpect.New(t, tsrv.URL)

	csrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth2":
		}
	}))
	defer csrv.Close()

	manager.MapClientStorage(clientStore(csrv.URL, true))
	srv = server.NewDefaultServer(manager)

	srv.SetModeAPI()

	srv.SetUserAuthorizationHandler(func(w http.ResponseWriter, r *http.Request) (userID string, err error) {
		userID = "000000"
		return
	})

	srv.SetClientInfoHandler(server.ClientFormHandler)

	resObj := e.GET("/authorize").
		WithQuery("response_type", "code").
		WithQuery("client_id", clientID).
		WithQuery("role", jwtRoleAPIserver).
		WithQuery("scope", "read, openid").
		WithQuery("state", "123").
		WithQuery("redirect_uri", csrv.URL+"/oauth2").
		WithQuery("code_challenge", s256ChallengeHash).
		WithQuery("code_challenge_method", "S256").
		Expect().Status(http.StatusOK)

	jsonBody := resObj.Body().Raw()

	jsonBody = strings.TrimSpace(jsonBody)

	// Decode the JSON string
	var responseData map[string]interface{}
	if err := json.Unmarshal([]byte(jsonBody), &responseData); err != nil {
		fmt.Println("error unmarshal the err: ", err)
	}

	code, ok := responseData["code"].(string)
	if !ok {
		fmt.Println("Failed to extract 'code' from JSON")
	}

	srv.SetUserOpenidHandler(OpenidService)

	resObj1 := e.POST("/token").
		WithFormField("redirect_uri", csrv.URL+"/oauth2").
		WithFormField("code", code).
		WithFormField("role", jwtRoleAPIserver). // will set the token duration specific for APIserver
		WithFormField("grant_type", "authorization_code").
		WithFormField("client_id", clientID).
		WithFormField("code_verifier", s256Challenge).
		Expect().
		Status(http.StatusOK).
		JSON().Object()

	responseData = resObj1.Raw()

	accessJWTexpiresIn, ok := responseData["expires_in"]
	if !ok {
		t.Error("Failed to extract 'expires_in' from the response")
	}

	// accessJWTexpiresIn is seconds, set it to days
	days := accessJWTexpiresIn.(float64) / (24 * 60 * 60)

	// the access token duration for APIServer role, by default is set to 15 days
	if days != float64(15) {
		t.Error("invalid jwt_access_token duration")
	}

	t.Logf("%#v\n", jwtAccessToken)
	t.Logf("%#v\n", jwtRefreshToken)
}

func TestAuthorizeCodeWithChallengeS256OpenidCustomAPIServerExp(t *testing.T) {
	mc := manage.ManagerConfig{
		AuthorizeCodeTokenCfgAccess:      24,
		AuthorizeCodeTokenCfgRefresh:     24 * 30,
		AuthorizeCodeAPIServerCfgAccess:  24 * 60,
		AuthorizeCodeAPIServerCfgRefresh: 24 * 90,
	}

	manager = manage.NewDefaultManager(mc)
	manager.MustTokenStorage(store.NewMemoryTokenStore())

	tsrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		testServer(t, w, r)
	}))
	defer tsrv.Close()

	e := httpexpect.New(t, tsrv.URL)

	csrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth2":
		}
	}))
	defer csrv.Close()

	manager.MapClientStorage(clientStore(csrv.URL, true))
	srv = server.NewDefaultServer(manager)

	srv.SetModeAPI()

	srv.SetUserAuthorizationHandler(func(w http.ResponseWriter, r *http.Request) (userID string, err error) {
		userID = "000000"
		return
	})

	srv.SetClientInfoHandler(server.ClientFormHandler)

	resObj := e.GET("/authorize").
		WithQuery("response_type", "code").
		WithQuery("client_id", clientID).
		WithQuery("role", jwtRoleAPIserver).
		WithQuery("scope", "read, openid").
		WithQuery("state", "123").
		WithQuery("redirect_uri", csrv.URL+"/oauth2").
		WithQuery("code_challenge", s256ChallengeHash).
		WithQuery("code_challenge_method", "S256").
		Expect().Status(http.StatusOK)

	jsonBody := resObj.Body().Raw()

	jsonBody = strings.TrimSpace(jsonBody)

	// Decode the JSON string
	var responseData map[string]interface{}
	if err := json.Unmarshal([]byte(jsonBody), &responseData); err != nil {
		fmt.Println("error unmarshal the err: ", err)
	}

	code, ok := responseData["code"].(string)
	if !ok {
		fmt.Println("Failed to extract 'code' from JSON")
	}

	srv.SetUserOpenidHandler(OpenidService)

	resObj1 := e.POST("/token").
		WithFormField("redirect_uri", csrv.URL+"/oauth2").
		WithFormField("code", code).
		WithFormField("role", jwtRoleAPIserver). // will set the token duration specific for APIserver
		WithFormField("grant_type", "authorization_code").
		WithFormField("client_id", clientID).
		WithFormField("code_verifier", s256Challenge).
		Expect().
		Status(http.StatusOK).
		JSON().Object()

	responseData = resObj1.Raw()

	accessJWTexpiresIn, ok := responseData["expires_in"]
	if !ok {
		t.Error("Failed to extract 'expires_in' from the response")
	}

	// accessJWTexpiresIn is seconds, set it to days
	days := accessJWTexpiresIn.(float64) / (24 * 60 * 60)

	// assert jwtAccessToken duration, here set to 60s
	// the access token duration for APIServer role has been set to 60day
	if days != float64(60) {
		t.Error("invalid jwt_access_token duration")
	}

	t.Logf("%#v\n", jwtAccessToken)
	t.Logf("%#v\n", jwtRefreshToken)
}

func TestAuthorizeCodeWithChallengeS256OpenidCustomTokenExp(t *testing.T) {
	tsrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		testServer(t, w, r)
	}))
	defer tsrv.Close()

	e := httpexpect.New(t, tsrv.URL)

	csrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth2":
		}
	}))
	defer csrv.Close()

	manager.MapClientStorage(clientStore(csrv.URL, true))
	srv = server.NewDefaultServer(manager)

	srv.SetModeAPI()

	srv.SetUserAuthorizationHandler(func(w http.ResponseWriter, r *http.Request) (userID string, err error) {
		userID = "000000"
		return
	})

	srv.SetClientInfoHandler(server.ClientFormHandler)

	resObj := e.GET("/authorize").
		WithQuery("response_type", "code").
		WithQuery("client_id", clientID).
		WithQuery("role", jwtRole).
		WithQuery("scope", "read, openid").
		WithQuery("state", "123").
		WithQuery("redirect_uri", csrv.URL+"/oauth2").
		WithQuery("code_challenge", s256ChallengeHash).
		WithQuery("code_challenge_method", "S256").
		Expect().Status(http.StatusOK)

	jsonBody := resObj.Body().Raw()

	jsonBody = strings.TrimSpace(jsonBody)

	// Decode the JSON string
	var responseData map[string]interface{}
	if err := json.Unmarshal([]byte(jsonBody), &responseData); err != nil {
		fmt.Println("error unmarshal the err: ", err)
	}

	code, ok := responseData["code"].(string)
	if !ok {
		fmt.Println("Failed to extract 'code' from JSON")
	}

	srv.SetUserOpenidHandler(OpenidService)

	resObj1 := e.POST("/token").
		WithFormField("redirect_uri", csrv.URL+"/oauth2").
		WithFormField("code", code).
		WithFormField("role", jwtRole).
		WithFormField("grant_type", "authorization_code").
		WithFormField("client_id", clientID).
		WithFormField("code_verifier", s256Challenge).
		Expect().
		Status(http.StatusOK).
		JSON().Object()

	responseData = resObj1.Raw()

	accessJWTexpiresIn, ok := responseData["expires_in"]
	if !ok {
		t.Error("Failed to extract 'expires_in' from the response")
	}

	// accessJWTexpiresIn is seconds, set it to days
	days := accessJWTexpiresIn.(float64) / (24 * 60 * 60)

	if days != float64(1) {
		t.Error("invalid jwt_access_token duration")
	}

	t.Logf("%#v\n", jwtAccessToken)
	t.Logf("%#v\n", jwtRefreshToken)
}

// validation access token
func validationAccessToken(t *testing.T, accessToken string) {

	req := httptest.NewRequest("GET", "http://example.com", nil)

	req.Header.Set("Authorization", "Bearer "+accessToken)

	ti, err := srv.ValidationBearerToken(req)
	if err != nil {
		t.Error(err.Error())
		return
	}
	if ti.GetClientID() != clientID {
		t.Error("invalid access token")
	}
}

//
// // TODO srv.HandleJWTokenAdminGetdata() Add tests for this method
// // TODO !!!! instead of having all methods create a new jwt.Handler maybee separate this logic ??
// // TODO see what's happend in the oauth_token when cutomer logout ??
