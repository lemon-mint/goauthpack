package goauthpack

import (
	"encoding/json"
	"time"

	"github.com/lemon-mint/macaronsign"
	"golang.org/x/crypto/argon2"
)

const sessionVersion = 0

var globalSigner *macaronsign.Signer

//InitSigner : Initialize the signer
func InitSigner(SecretKey string, exp int64) {
	Signer := macaronsign.NewSigner(exp, argon2.IDKey([]byte(SecretKey), []byte(SecretKey), 1, 1024*16, 1, 64), 0, 0)
	globalSigner = &Signer
}

var _ = func() int {
	InitSigner(makeRandString(32), 86400)
	return 0
}

//Session struct
type Session struct {
	SessionID string            `json:"sessionid"`
	Version   int               `json:"v"`
	Issue     int               `json:"iat"`
	UserName  string            `json:"sub"`
	Data      map[string]string `json:"data"`
}

//NewSession : Create New Session String
func NewSession(UserName string, Data map[string]string) (string, error) {
	jsondata, err := json.Marshal(Session{
		SessionID: makeRandString(8),
		Version:   sessionVersion,
		Issue:     int(time.Now().UTC().UnixNano()),
		UserName:  UserName,
		Data:      Data,
	})
	if err != nil {
		return "", err
	}
	return globalSigner.SignAndEncrypt(jsondata), nil
}
