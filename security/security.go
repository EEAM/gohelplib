package security

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
  "time"

	errmgmt "github.com/EEAM/gohelplib/errormanagement"
	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
)

type Maker interface {
	CreateToken(username string, duration time.Duration) (string, error)
	VerifyToken(token string) (*Payload, error)
}
type Payload struct {
	ID        uuid.UUID `json:"id"`
	Username  string    `json:"username"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiredAt time.Time `json:"expired_at"`
}

type JWTMaker struct {
	secretKey string
}

var (
	ErrInvalidToken = errors.New("token is invalid")
	ErrExpiredToken = errors.New("token has expired")
)

func (payload *Payload) Valid() error {
	if time.Now().After(payload.ExpiredAt) {
		return ErrExpiredToken
	}
	return nil
}

func (maker *JWTMaker) VerifyToken(token string) (*Payload, error) {
	keyFunc := func(token *jwt.Token) (interface{}, error) {
		_, ok := token.Method.(*jwt.SigningMethodHMAC)
		if !ok {
			return nil, ErrInvalidToken
		}
		return []byte(maker.secretKey), nil
	}

	jwtToken, err := jwt.ParseWithClaims(token, &Payload{}, keyFunc)
	if err != nil {
		verr, ok := err.(*jwt.ValidationError)
		if ok && errors.Is(verr.Inner, ErrExpiredToken) {
			return nil, ErrExpiredToken
		}
		return nil, ErrInvalidToken
	}

	payload, ok := jwtToken.Claims.(*Payload)
	if !ok {
		return nil, ErrInvalidToken
	}

	return payload, nil
}

func (maker *JWTMaker) CreateToken(username string, duration time.Duration) (string, error) {
	payload, err := NewPayload(username, duration)
	if err != nil {
		return "", err
	}

	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, payload)
	return jwtToken.SignedString([]byte(maker.secretKey))
}

func ParseWithClaims(tokenString string) (jwt.Claims, error) {

	token, err := jwt.Parse(tokenString, nil)
	if token == nil {
		return nil, err
	}
	claims, _ := token.Claims.(jwt.MapClaims)

	for key, value := range claims {
		fmt.Printf("%s\t%v\n", key, value)
	}
	return claims, nil
}

func NewPayload(username string, duration time.Duration) (*Payload, error) {
	tokenID, err := uuid.NewRandom()
	if err != nil {
		return nil, err
	}

	payload := &Payload{
		ID:        tokenID,
		Username:  username,
		IssuedAt:  time.Now(),
		ExpiredAt: time.Now().Add(duration),
	}
	return payload, nil
}

func AquireTokenUrlEncoded(endpointUrl string, queryString url.Values) (string, error) {

	client := &http.Client{}
	req, err := http.NewRequest("POST", endpointUrl, strings.NewReader(queryString.Encode())) // URL-encoded payload
	if err != nil {
		return "", fmt.Errorf("error for creating http.Request for the endpoint: %v and url encoded parameter:\n%v", endpointUrl, queryString.Encode())
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Content-Length", strconv.Itoa(len(queryString.Encode())))
	resp, err := client.Do(req)

	if err != nil {
		return "", fmt.Errorf("error for creating http.Request for the endpoint: %v and url encoded parameter:\n%v", endpointUrl, queryString.Encode())
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	bodyS := string(body)

	if err != nil && resp.StatusCode == 200 {
		return "", errmgmt.ErrorAccessTokenInvalid{Url: endpointUrl, Code: resp.StatusCode, Message: bodyS}
	}

	return bodyS, nil
}
