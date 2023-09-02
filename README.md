# Golang OpenID Connect

> Forked from https://github.com/go-oauth2/oauth2 this implementation add the OpenID layer on top of the oauth2 protocol.

> This implementation aim to be a ready to use authorization and authentification service, implemented only with Authorization code grant type(at this time). 


## Note

> Project under development


## Protocol Flow

```text
     +--------+                                             +-------------------------------------+
     |        |---------- Authorization Request ----------> |           Authorization             |
     |        |                                             |               Server                |
     |        |<--------- Authorization Code -------------  | - insure the client is registered   |
     |        |                                             | - if ok deliver an authorizationCode|
     |        |                                             +-------------------------------------+
     |        |
     |        |                                             +------------------------------------+
     |        |-Authorization Code with "openid" as scope-->|           Authorization            |
     |        |                                             |               Server               |
     |        |                                             | - create accessCode(ac)            |
     | client |                                             | - create RefreshCode(rc)           |
     |        |                                             | - create access and refresh jwt    |
     |        |<------- return access jwt(at least)-------- |(including userCredential,ac and rc)|
     |        |                                             | - customize the payload to return |
     |        |                                             +------------------------------------+
     |        |
     |        |                                             +------------------------------------+
     |        |------------ Access Token -----------------> |           Resource                 |
     |        |                                             |            Server                  |
     |        |<----------- Protected Resource ------------ | - valid the jwt                    |
     +--------+                                             +------------------------------------+
```

## Advantage
- You can still use this package as the go-oauth2/oauth there is no breacking change
- This package can be use with a mobile app as it can return the Authorization Code(instead of just redirecting)
- The possibility to crete the jwt with various keyID, secretKey(depending on the user scope for ex)
- After the jwt(accessToken and refreshToken) has been created, before they are returned to the client the payload may be customized(the refreshToken be saved in DB and not returning to the client for ex)
- As this package is a fork of go-oauth2/oauth2 all its store implementations are available

## Limitation
- The encoding of the jwt is limited to "HS256"
- Implemented only with Authorization code grant type 


## Quick Start

### Download and install

```bash
go get github.com/djedjethai/go-oauth2-openid
```

### Create file `server.go` (we use mongo storage)

```go
    import (
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	// "time"

	// "github.com/go-oauth2/oauth2/v4/generates"
	"server/internal/handlers"

	"github.com/go-oauth2/oauth2/v4/errors"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/models"
	"github.com/go-oauth2/oauth2/v4/server"

	mongo "gopkg.in/go-oauth2/mongo.v3"
)

var (
	dumpvar   bool
	idvar     string
	secretvar string
	domainvar string
	portvar   int
)

// TODO
// right now as a client is register in db, it won't be updated in case of modification
// means the updates won't take effect........ see in the mongo client...

func init() {
	// credential for the client
	flag.BoolVar(&dumpvar, "d", true, "Dump requests and responses")
	flag.StringVar(&idvar, "i", "222222", "The client id being passed in")
	flag.StringVar(&secretvar, "s", "22222222", "The client secret being passed in")
	flag.StringVar(&domainvar, "r", "http://localhost:3000", "The domain of the redirect url")
	flag.IntVar(&portvar, "p", 9096, "the base port for the server")
}

const (
	// credential for the preOrder service
	idPreorder     string = "888888"
	secretPreorder string = "88888888"
	domainPreorder string = "http://localhost:8081"

	dbUser     = "postgres"
	dbHost     = "localhost"
	dbPassword = "password"
	dbDatabase = "users"
	dbSSL      = "disable"
	dbPort     = "5432"
)

func main() {
	flag.Parse()

	manager := manage.NewDefaultManager()

	// set connectionTimeout(7s) and the requestsTimeout(5s) // is optional
	storeConfigs := mongo.NewStoreConfig(7, 5)

	mongoConf := mongo.NewConfigNonReplicaSet(
		"mongodb://127.0.0.1:27017",
		"oauth2",   // database name
		"admin",    // username to authenticate with db
		"password", // password to authenticate with db
		"serviceName",
	)

	// use mongodb token store
	manager.MapTokenStorage(
		mongo.NewTokenStore(mongoConf, storeConfigs), // with timeout
	)

	clientStore := mongo.NewClientStore(mongoConf, storeConfigs) // with timeout

	manager.MapClientStorage(clientStore)

	// register the front-end
	clientStore.Create(&models.Client{
		ID:     idvar,
		Secret: secretvar,
		Domain: domainvar,
		UserID: "frontend",
	})

	// register another service
	clientStore.Create(&models.Client{
		ID:     idPreorder,
		Secret: secretPreorder,
		Domain: domainPreorder,
		UserID: "prePost",
	})

	srv := server.NewServer(server.NewConfig(), manager)

    // *** NOTE *** 
	// set the oauth package to work without browser
	// the token will be return as a json payload
	srv.SetModeAPI()

	// handlers will handle all handlers
	handler := handlers.NewHandlers(dumpvar, srv)

    /*
    * set functions which are allowing 
    * 1 - controle of the user Authorization or/and authentication
    * 2 - settings of the jwt keyID, secretKey and user credentials
    * 3 - customize the payload to return to client
    **/
	// 1 - set the authorization staff
	srv.SetUserAuthorizationHandler(handler.UserAuthorizeHandler)

	// 2 - set the openid staff
	srv.SetUserOpenidHandler(handler.UserOpenidHandler)

	// 3 - set the func to, before to send it, customize the token payload
	srv.SetCustomizeTokenPayloadHandler(handler.UserCustomizeTokenPayloadHandler)

	srv.SetInternalErrorHandler(func(err error) (re *errors.Response) {
		log.Println("Internal Error:", err.Error())
		return
	})

	srv.SetResponseErrorHandler(func(re *errors.Response) {
		log.Println("Response Error:", re.Error.Error())
	})

	// Endpoints for the front-end
	// (use this service for the example but a specific users' service may be better in some case)
	http.HandleFunc("/api/v1/auth/signup", handler.SignupHandler)
	http.HandleFunc("/api/v1/auth/signin", handler.SigninHandler)
	http.HandleFunc("/api/v1/auth/signout", handler.SignoutHandler)

	// Endpoints specific to validate the authorization
	http.HandleFunc("/api/v1/auth/oauth/authorize", handler.Authorize)
	http.HandleFunc("/api/v1/auth/oauth/token", handler.Token)

	// Endpoint which validate a client's token and the given permission
	http.HandleFunc("/api/v1/auth/jwtvalidation", handler.JwtValidation)
	http.HandleFunc("/api/v1/auth/jwtgetdata", handler.JwtGetdata)
	http.HandleFunc("/api/v1/auth/permission", handler.ValidPermission)
	http.HandleFunc("/api/v1/auth/refreshopenid", handler.RefreshOpenid)

	log.Printf("Server is running at %d port.\n", portvar)
	log.Printf("Point your OAuth client Auth endpoint to %s:%d%s", "http://localhost", portvar, "/oauth/authorize")
	log.Printf("Point your OAuth client Token endpoint to %s:%d%s", "http://localhost", portvar, "/oauth/token")
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", portvar), nil))
}


```

### The handlers

```go
    package handlers

import (
	"context"
	"fmt"
	"net/http"
	// "net/url"
	"os"
	"sync"

	"github.com/go-oauth2/oauth2/v4/server"
)

unc NewAuthentication(srv *server.Server) Authentication {

	return Authentication{
		srv:           srv,
		extStore:      make(map[string]interface{}),
		databaseUsers: make(map[string]interface{}),
	}
}

func (a Authentication) Authorize(w http.ResponseWriter, r *http.Request) {

	if carryon := allowCORS(w, r); !carryon {
		return
	}

	if dumpvar {
		dumpRequest(os.Stdout, "authorize", r)
	}

	err := a.srv.HandleAuthorizeRequest(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}

}

func (a Authentication) RefreshOpenid(w http.ResponseWriter, r *http.Request) {

	// see the incoming r
	if dumpvar {
		_ = dumpRequest(os.Stdout, "openidRefresh", r) // Ignore the error
	}

	// pass the request to the openid logic
	_ = a.srv.RefreshOpenidToken(context.TODO(), w, r)

}

// TODO also see where to set the token validity ???
func (a Authentication) UserCustomizeTokenPayloadHandler(r *http.Request, data map[string]interface{}) (error, interface{}) {

	// Do whatever we like with the returned JWT
    // save the the refresh JWT in DB for ex
	fmt.Println("app/authentication.go - UserCustomizeTokenPayloadHandler, refreshTK: ", data["refresh_token"])

    // for ex
	fmt.Println("app/authentication.go - UserCustomizeTokenPayloadHandler, userAccount: ", r.FormValue("email"))

	// return only the access_token for ex
	return nil, data["access_token"]
}

// configure the jwt setting and user credentials to pass into 
func (a Authentication) UserOpenidHandler(w http.ResponseWriter, r *http.Request) (jwtInfo map[string]interface{}, keyID string, secretKey string, encoding string, err error) {
	if dumpvar {
		_ = dumpRequest(os.Stdout, "userOpenidHandler", r) // Ignore the error
	}

	err = nil

	keyID = "theKeyID"
	secretKey = "mySecretKey"
	encoding = "HS256"

	// create the data we like to set into the jwt token
	jwtInfo = make(map[string]interface{})

	jwtInfo["name"] = "Robert"
	jwtInfo["age"] = 35
	jwtInfo["city"] = "London"

	return
}

// UserOpenIDHandler will query the userData itself
// This is link to signin and signup handlers implementation, see the examples
func (a Authentication) UserAuthorizeHandler(w http.ResponseWriter, r *http.Request) (userID string, err error) {

	if dumpvar {
		_ = dumpRequest(os.Stdout, "userAuthorizeHandler", r) // Ignore the error
	}

	clientID := r.Form.Get("client_id")

	switch clientID {
	case "222222":

		a.RLock()
		uid, ok := a.extStore[fmt.Sprintf("LoggedInUserID-%v", r.Form.Get("email"))]
		a.RUnlock()
		if !ok {
			if r.Form == nil {
				r.ParseForm()
			}

			w.WriteHeader(http.StatusOK)
			return
		}

		fmt.Println("Authentication.go see the req, look for user cred: ", r)

		userID = uid.(string)

		a.Lock()
		delete(a.extStore, fmt.Sprintf("LoggedInUserID-%v", r.Form.Get("email")))
		a.Unlock()
		return
	case "888888":

		a.RLock()
		uid, ok := a.extStore[fmt.Sprintf("LoggedInUserID-%v", r.Form.Get("client_id"))]
		a.RUnlock()
		if !ok {
			if r.Form == nil {
				r.ParseForm()
			}

			w.WriteHeader(http.StatusOK)
			return
		}

		userID = uid.(string)

		a.Lock()
		delete(a.extStore, fmt.Sprintf("LoggedInUserID-%v", r.Form.Get("client_id")))
		a.Unlock()
		return
	default:
		userID = ""
		return
	}
}



```

### Open in your web browser
**Authorization Request**:
[http://localhost:9096/authorize?client_id=000000&response_type=code](http://localhost:9096/authorize?client_id=000000&response_type=code)

**Grant Token Request**:
[http://localhost:9096/token?grant_type=client_credentials&client_id=000000&client_secret=999999&scope=read](http://localhost:9096/token?grant_type=client_credentials&client_id=000000&client_secret=999999&scope=read, openid)



## Example(under development)

> 


## Store Implements

- [BuntDB](https://github.com/tidwall/buntdb)(default store)
- [Redis](https://github.com/go-oauth2/redis)
- [MongoDB](https://github.com/go-oauth2/mongo)
- [MySQL](https://github.com/go-oauth2/mysql)
- [MySQL (Provides both client and token store)](https://github.com/imrenagi/go-oauth2-mysql)
- [PostgreSQL](https://github.com/vgarvardt/go-oauth2-pg)
- [DynamoDB](https://github.com/contamobi/go-oauth2-dynamodb)
- [XORM](https://github.com/techknowlogick/go-oauth2-xorm)
- [XORM (MySQL, client and token store)](https://github.com/rainlay/go-oauth2-xorm)
- [GORM](https://github.com/techknowlogick/go-oauth2-gorm)
- [Firestore](https://github.com/tslamic/go-oauth2-firestore)
- [Hazelcast](https://github.com/clowre/go-oauth2-hazelcast) (token only)

## Handy Utilities

- [OAuth2 Proxy Logger (Debug utility that proxies interfaces and logs)](https://github.com/aubelsb2/oauth2-logger-proxy)

## MIT License

Copyright (c) 2016 Lyric
Copyright (c) 2023 Jerome Bidault

[build-status-url]: https://travis-ci.org/go-oauth2/oauth2
[build-status-image]: https://travis-ci.org/go-oauth2/oauth2.svg?branch=master
[codecov-url]: https://codecov.io/gh/go-oauth2/oauth2
[codecov-image]: https://codecov.io/gh/go-oauth2/oauth2/branch/master/graph/badge.svg
[reportcard-url]: https://goreportcard.com/report/github.com/go-oauth2/oauth2/v4
[reportcard-image]: https://goreportcard.com/badge/github.com/go-oauth2/oauth2/v4
[godoc-url]: https://godoc.org/github.com/go-oauth2/oauth2/v4
[godoc-image]: https://godoc.org/github.com/go-oauth2/oauth2/v4?status.svg
[license-url]: http://opensource.org/licenses/MIT
[license-image]: https://img.shields.io/npm/l/express.svg
