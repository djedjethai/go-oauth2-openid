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

// TODO
// // test openid
// func TestAuthorizeCodeWithChallengeS256OpenidDefault(t *testing.T) {
// 	tsrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 		testServer(t, w, r)
// 	}))
// 	defer tsrv.Close()
//
// 	e := httpexpect.New(t, tsrv.URL)
//
// 	csrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 		switch r.URL.Path {
// 		case "/oauth2":
// 		}
// 	}))
// 	defer csrv.Close()
//
// 	manager.MapClientStorage(clientStore(csrv.URL, true))
// 	srv = server.NewDefaultServer(manager)
//
// 	srv.SetModeAPI()
//
// 	srv.SetUserAuthorizationHandler(func(w http.ResponseWriter, r *http.Request) (userID string, err error) {
// 		userID = "000000"
// 		return
// 	})
//
// 	srv.SetCustomizeTokenPayloadHandler(func(r *http.Request, data map[string]interface{}) (error, interface{}) {
//
// 		fmt.Println("In the SetCustomizeTokenPayloadHandler, data: ", data)
//
// 		return nil, data
// 	})
//
// 	srv.SetClientInfoHandler(server.ClientFormHandler)
//
// 	resObj := e.GET("/authorize").
// 		WithQuery("response_type", "code").
// 		WithQuery("client_id", clientID).
// 		WithQuery("scope", "read, openid").
// 		WithQuery("state", "123").
// 		WithQuery("redirect_uri", csrv.URL+"/oauth2").
// 		WithQuery("code_challenge", s256ChallengeHash).
// 		WithQuery("code_challenge_method", "S256").
// 		Expect().Status(http.StatusOK)
//
// 	jsonBody := resObj.Body().Raw()
//
// 	jsonBody = strings.TrimSpace(jsonBody)
//
// 	// Decode the JSON string
// 	var responseData map[string]interface{}
// 	if err := json.Unmarshal([]byte(jsonBody), &responseData); err != nil {
// 		fmt.Println("error unmarshal the err: ", err)
// 	}
//
// 	code, ok := responseData["code"].(string)
// 	if !ok {
// 		fmt.Println("Failed to extract 'code' from JSON")
// 	}
//
// 	// Log or use the extracted code as needed
// 	fmt.Printf("Authorization Code: %s\n", code)
//
// 	resObj1 := e.POST("/token").
// 		WithFormField("redirect_uri", csrv.URL+"/oauth2").
// 		WithFormField("code", code).
// 		WithFormField("grant_type", "authorization_code").
// 		WithFormField("client_id", clientID).
// 		WithFormField("code_verifier", s256Challenge).
// 		Expect().
// 		Status(http.StatusOK).
// 		JSON().Object()
//
// 	responseData = resObj1.Raw()
//
// 	// Extract the jwt_refresh_token and jwt_access_token
// 	jwtRefreshToken, ok := responseData["jwt_refresh_token"].(string)
// 	if !ok {
// 		fmt.Println("Failed to extract 'jwt_refresh_token' from the response")
// 	}
//
// 	jwtAccessToken, ok := responseData["jwt_access_token"].(string)
// 	if !ok {
// 		fmt.Println("Failed to extract 'jwt_access_token' from the response")
// 	}
//
// 	// Use the extracted values as needed
// 	fmt.Printf("JWT Refresh Token: %s\n", jwtRefreshToken)
// 	fmt.Printf("JWT Access Token: %s\n", jwtAccessToken)
//
// 	// TODO extract the values from jwt and assert on it
// 	// (the key and secretKey are the default one see server/server.go)
// }

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

		fmt.Println("In the SetCustomizeTokenPayloadHandler, data: ", data)

		return nil, data
	})

	srv.SetClientInfoHandler(server.ClientFormHandler)

	var keyID = "theKeyID"
	var secretKey = "mySecretKey"
	var encoding = "HS256"

	// custom the jwt set the 'key', 'secretKey', encoding, error
	// NOTE got user data from the http.Request
	// NOTE and keys can be specific to role
	// TODO see the default jwt expiration + test the customized way
	srv.SetUserOpenidHandler(func(w http.ResponseWriter, r *http.Request) (map[string]interface{}, string, string, string, error) {
		var err error = nil
		// keyID = "theKeyID"
		// secretKey = "mySecretKey"
		// encoding = "HS256"

		jwtInfo := make(map[string]interface{})
		jwtInfo["name"] = "Robert"
		jwtInfo["age"] = 35
		jwtInfo["city"] = "London"

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

	// Log or use the extracted code as needed
	fmt.Printf("Authorization Code: %s\n", code)

	resObj1 := e.POST("/token").
		WithFormField("redirect_uri", csrv.URL+"/oauth2").
		WithFormField("code", code).
		WithFormField("grant_type", "authorization_code").
		WithFormField("client_id", clientID).
		WithFormField("code_verifier", s256Challenge).
		Expect().
		Status(http.StatusOK).
		JSON().Object()

	responseData = resObj1.Raw()

	// Extract the jwt_refresh_token and jwt_access_token
	jwtRefreshToken, ok := responseData["jwt_refresh_token"].(string)
	if !ok {
		fmt.Println("Failed to extract 'jwt_refresh_token' from the response")
	}

	jwtAccessToken, ok := responseData["jwt_access_token"].(string)
	if !ok {
		fmt.Println("Failed to extract 'jwt_access_token' from the response")
	}

	// Use the extracted values as needed
	fmt.Printf("JWT Refresh Token: %s\n", jwtRefreshToken)
	fmt.Printf("JWT Access Token: %s\n", jwtAccessToken)

	// NOTE set that in a separate test ??????????????????????/

	// test jwtAccessToken data
	// TODO test expire time, and assert
	r := &http.Request{}
	data, err := srv.HandleJWTokenGetdata(context.TODO(), r, jwtAccessToken, keyID, secretKey, encoding)
	if err != nil {
		fmt.Println("error getting data from jwt")
	}

	fmt.Println("seee the data from jwtAccessToken: ", data)

	// TODO test expire time, and assert
	data, err = srv.HandleJWTokenGetdata(context.TODO(), r, jwtRefreshToken, keyID, secretKey, encoding)
	if err != nil {
		fmt.Println("error getting data from jwt")
	}

	fmt.Println("seee the data from jwtRefreshToken: ", data)

	// TODO test jwt token validity.......

}

// get jwt
// add SetCostumizeToken
// refresh jwt
// valid jwt
// voir l'histoire ou j'ajoute le jwt to the client ????
// test return the token(instead of redirect)

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
