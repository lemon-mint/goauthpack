package goauthpack

import (
	"encoding/json"
	"errors"
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

//ErrInvaild :Errors that occur when the session is invalid
var ErrInvaild error = errors.New("invalid Session")

//ReadSession : Verify the session
func ReadSession(session string) (UserName string, Data map[string]string, err error) {
	jsondata, err := globalSigner.DecryptAndVerify(session)
	if err != nil {
		return "", nil, ErrInvaild
	}
	s := new(Session)
	err = json.Unmarshal([]byte(jsondata), s)
	if err != nil {
		return "", nil, ErrInvaild
	}
	return s.UserName, s.Data, nil
}
