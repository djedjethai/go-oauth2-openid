package generates

import (
	"context"
	"encoding/base64"
	"fmt"
	// "reflect"
	// "log"
	"strings"
	"time"

	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/errors"
	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
)

// JWTAccessClaims jwt claims
type JWTAccessClaims struct {
	jwt.StandardClaims
	UserInfo     oauth2.UserInfo `json:"userInfo"`
	AccessToken  string          `json:"accessToken"`
	RefreshToken string          `json:"refreshToken"`
}

// Valid claims verification
func (a *JWTAccessClaims) Valid() error {
	if time.Unix(a.ExpiresAt, 0).Before(time.Now()) {
		return errors.ErrInvalidAccessToken
	}
	return nil
}

// JWTAccessGenerate generate the jwt access token
type JWTAccessGenerate struct {
	SignedKeyID  string // identifiant refering to the SignedKey
	SignedKey    []byte // secret key
	SignedMethod jwt.SigningMethod
}

func NewDefaultJWTAccessGenerate() *JWTAccessGenerate {
	return &JWTAccessGenerate{}

}

func (a *JWTAccessGenerate) SetJWTAccessGenerate(kid string, key []byte, meth ...string) {
	method := getSignInMethod(meth[0])
	if len(meth) == 0 || method == nil {
		method = jwt.SigningMethodHS256
	}
	a.SignedKeyID = kid
	a.SignedKey = key
	a.SignedMethod = method
}

// // NewJWTAccessGenerate create to generate the jwt access token instance
// func NewJWTAccessGenerate(kid string, key []byte, meth ...string) *JWTAccessGenerate {
// 	method := getSignInMethod(meth[0])
// 	if len(meth) == 0 || method == nil {
// 		method = jwt.SigningMethodHS256
// 	}
// 	return &JWTAccessGenerate{
// 		SignedKeyID:  kid,
// 		SignedKey:    key,
// 		SignedMethod: method,
// 	}
// }

// NOTE Token based on the UUID generated token
func (a *JWTAccessGenerate) TokenOpenid(ctx context.Context, ti oauth2.TokenInfo, isGenRefresh bool, ui oauth2.UserInfo) (string, string, error) {

	claims := &JWTAccessClaims{
		StandardClaims: jwt.StandardClaims{
			Audience:  ti.GetClientID(),
			Subject:   ti.GetUserID(),
			ExpiresAt: ti.GetAccessCreateAt().Add(ti.GetAccessExpiresIn()).Unix(),
		},
		UserInfo:     ui,
		AccessToken:  ti.GetAccess(),
		RefreshToken: ti.GetRefresh(),
	}

	token := jwt.NewWithClaims(a.SignedMethod, claims)
	if a.SignedKeyID != "" {
		token.Header["kid"] = a.SignedKeyID
	}
	var key interface{}
	if a.isEs() {
		v, err := jwt.ParseECPrivateKeyFromPEM(a.SignedKey)
		if err != nil {
			return "", "", err
		}
		key = v
	} else if a.isRsOrPS() {
		v, err := jwt.ParseRSAPrivateKeyFromPEM(a.SignedKey)
		if err != nil {
			return "", "", err
		}
		key = v
	} else if a.isHs() {
		key = a.SignedKey
	} else if a.isEd() {
		v, err := jwt.ParseEdPrivateKeyFromPEM(a.SignedKey)
		if err != nil {
			return "", "", err
		}
		key = v
	} else {
		return "", "", errors.New("unsupported sign method")
	}

	access, err := token.SignedString(key)
	if err != nil {
		return "", "", err
	}
	refresh := ""

	// generate a refresh JWT
	if isGenRefresh {
		claims.StandardClaims.ExpiresAt = ti.GetAccessCreateAt().Add(ti.GetRefreshExpiresIn()).Unix()
		token = jwt.NewWithClaims(a.SignedMethod, claims)
		if a.SignedKeyID != "" {
			token.Header["kid"] = a.SignedKeyID
		}

		refresh, err = token.SignedString(key)
		if err != nil {
			return "", "", err
		}
	}

	return access, refresh, nil
}

// TODO implement refresh jwtOpenidToken or isGenRferesh already do it ?

func (a *JWTAccessGenerate) ValidOpenidToken(ctx context.Context, secret, tokenString string) bool {
	if a.isHs() {
		var secretKey = []byte(secret)

		// Parse the token
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// Return the secret key for verification
			return secretKey, nil
		})
		if err != nil {
			// Handle parsing error
		}

		// Check if the token is valid
		if token.Valid {
			// Token is valid, proceed with using the token claims
			claims := token.Claims.(jwt.MapClaims)
			fmt.Println("See Token name: ", claims["Name"])

			// validate expire date
			err := claims.Valid()
			if err != nil {
				return false
			}

			return true
			// Access claims using claims["key"] or type assertion based on your custom claims
		} else {
			return false
			// Token is invalid
		}
	}
	return false
}

func (a *JWTAccessGenerate) isEs() bool {
	return strings.HasPrefix(a.SignedMethod.Alg(), "ES")
}

func (a *JWTAccessGenerate) isRsOrPS() bool {
	isRs := strings.HasPrefix(a.SignedMethod.Alg(), "RS")
	isPs := strings.HasPrefix(a.SignedMethod.Alg(), "PS")
	return isRs || isPs
}

func (a *JWTAccessGenerate) isHs() bool {
	return strings.HasPrefix(a.SignedMethod.Alg(), "HS")
}

func (a *JWTAccessGenerate) isEd() bool {
	return strings.HasPrefix(a.SignedMethod.Alg(), "Ed")
}

// Token based on the UUID generated token
func (a *JWTAccessGenerate) Token(ctx context.Context, data *oauth2.GenerateBasic, isGenRefresh bool) (string, string, error) {
	claims := &JWTAccessClaims{
		StandardClaims: jwt.StandardClaims{
			Audience:  data.Client.GetID(),
			Subject:   data.UserID,
			ExpiresAt: data.TokenInfo.GetAccessCreateAt().Add(data.TokenInfo.GetAccessExpiresIn()).Unix(),
		},
	}

	token := jwt.NewWithClaims(a.SignedMethod, claims)
	if a.SignedKeyID != "" {
		token.Header["kid"] = a.SignedKeyID
	}
	var key interface{}
	if a.isEs() {
		v, err := jwt.ParseECPrivateKeyFromPEM(a.SignedKey)
		if err != nil {
			return "", "", err
		}
		key = v
	} else if a.isRsOrPS() {
		v, err := jwt.ParseRSAPrivateKeyFromPEM(a.SignedKey)
		if err != nil {
			return "", "", err
		}
		key = v
	} else if a.isHs() {
		key = a.SignedKey
	} else if a.isEd() {
		v, err := jwt.ParseEdPrivateKeyFromPEM(a.SignedKey)
		if err != nil {
			return "", "", err
		}
		key = v
	} else {
		return "", "", errors.New("unsupported sign method")
	}

	access, err := token.SignedString(key)
	if err != nil {
		return "", "", err
	}
	refresh := ""

	if isGenRefresh {
		t := uuid.NewSHA1(uuid.Must(uuid.NewRandom()), []byte(access)).String()
		refresh = base64.URLEncoding.EncodeToString([]byte(t))
		refresh = strings.ToUpper(strings.TrimRight(refresh, "="))
	}

	return access, refresh, nil
}

func getSignInMethod(sm string) jwt.SigningMethod {
	switch sm {
	case "HS256":
		return jwt.SigningMethodHS256
	case "HS384":
		return jwt.SigningMethodHS384
	case "HS512":
		return jwt.SigningMethodHS512
	case "RS256":
		return jwt.SigningMethodRS256
	case "RS384":
		return jwt.SigningMethodRS384
	case "RS512":
		return jwt.SigningMethodRS512
	case "ES256":
		return jwt.SigningMethodHS256
	case "ES384":
		return jwt.SigningMethodES384
	case "ES512":
		return jwt.SigningMethodES512
	case "PS256":
		return jwt.SigningMethodPS256
	case "PS384":
		return jwt.SigningMethodPS384
	case "PS512":
		return jwt.SigningMethodPS512
	case "EdDsa":
		return jwt.SigningMethodEdDSA
	default:
		return nil
	}
}

// // NOTE NewJWTAccessGenerate create to generate the jwt access token instance
// func NewJWTAccessGenerateWithStringMethod(kid string, key []byte, method string) *JWTAccessGenerate {
// 	sm := getSignInMethod(method)
// 	if sm == nil {
// 		return nil
// 	}
// 	log.Println("jwt_access.go NewJWTAccessGenerate kid: ", kid)
// 	log.Println("jwt_access.go NewJWTAccessGenerate key: ", key)
// 	return &JWTAccessGenerate{
// 		SignedKeyID:  kid,
// 		SignedKey:    key,
// 		SignedMethod: sm,
// 	}
// }

// func (a *JWTAccessGenerate) ClaimProvider(ctx context.Context, data oauth2.GenerateBasic) *JWTAccessClaims {
// 	return &JWTAccessClaims{
// 		StandardClaims: jwt.StandardClaims{
// 			Audience:  data.Client.GetID(),
// 			Subject:   data.UserID,
// 			ExpiresAt: data.TokenInfo.GetAccessCreateAt().Add(data.TokenInfo.GetAccessExpiresIn()).Unix(),
// 		},
// 	}
//
// }
//
// func (a *JWTAccessGenerate) AddOpenidToClaim(claims *JWTAccessClaims, ti oauth2.TokenInfo, userInfo interface{}, isGenRefresh bool) (string, string, error) {
// 	userInfoTyped, ok := userInfo.(UserInfo)
// 	if !ok {
// 		fmt.Println("userInfo is not of type UserInfo")
// 		return "", "", errors.ErrInvalidRequest
// 	}
//
// 	// Set the fields in JWTAccessClaims from userInfoTyped
// 	claims.Name = userInfoTyped.Name
// 	claims.Email = userInfoTyped.Email
// 	claims.Role = userInfoTyped.Role
//
// 	claims.AccessToken = ti.GetAccess()
// 	claims.RefreshToken = ti.GetRefresh()
//
// 	token := jwt.NewWithClaims(a.SignedMethod, claims)
// 	if a.SignedKeyID != "" {
// 		token.Header["kid"] = a.SignedKeyID
// 	}
// 	var key interface{}
// 	if a.isEs() {
// 		v, err := jwt.ParseECPrivateKeyFromPEM(a.SignedKey)
// 		if err != nil {
// 			return "", "", err
// 		}
// 		key = v
// 	} else if a.isRsOrPS() {
// 		v, err := jwt.ParseRSAPrivateKeyFromPEM(a.SignedKey)
// 		if err != nil {
// 			return "", "", err
// 		}
// 		key = v
// 	} else if a.isHs() {
// 		key = a.SignedKey
// 	} else if a.isEd() {
// 		v, err := jwt.ParseEdPrivateKeyFromPEM(a.SignedKey)
// 		if err != nil {
// 			return "", "", err
// 		}
// 		key = v
// 	} else {
// 		return "", "", errors.New("unsupported sign method")
// 	}
//
// 	access, err := token.SignedString(key)
// 	if err != nil {
// 		return "", "", err
// 	}
// 	refresh := ""
//
// 	if isGenRefresh {
// 		t := uuid.NewSHA1(uuid.Must(uuid.NewRandom()), []byte(access)).String()
// 		refresh = base64.URLEncoding.EncodeToString([]byte(t))
// 		refresh = strings.ToUpper(strings.TrimRight(refresh, "="))
// 	}
//
// 	return access, refresh, nil
//
// }
//
