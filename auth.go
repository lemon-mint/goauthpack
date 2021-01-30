package goauthpack

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"io"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

const recommendedAlgorithm = 0
const minimumRequirement = 0

func hashpass(data, salt []byte, version int) []byte {
	if version == 0 {
		//argon2 High
		return argon2.IDKey(data, salt, 5, 32*1024, 2, 32)
	}
	return nil
}

//structure : {version}${salt}${hash}$...(etc)
func genAuthString(password string, version int) string {
	salt := make([]byte, 16)
	io.ReadFull(rand.Reader, salt)
	hash := hashpass([]byte(password), salt, version)
	return strconv.Itoa(version) +
		"$" + base64.RawURLEncoding.EncodeToString(salt) +
		"$" + base64.RawURLEncoding.EncodeToString(hash)
}

func verifyAuthString(AuthString string, password string) (success bool, updateRequired bool, CurrentVersion int) {
	var version int
	parts := strings.Split(AuthString, "$")
	version, err := strconv.Atoi(parts[0])
	if err != nil {
		return false, false, 0
	}
	salt, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false, false, version
	}
	hash, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return false, false, version
	}
	passwordHash := hashpass([]byte(password), salt, version)
	if subtle.ConstantTimeCompare(hash, passwordHash) != 1 {
		return false, false, version
	}
	if bytes.Compare(hash, passwordHash) == 1 {
		return false, false, version
	}
	if version < minimumRequirement {
		return true, true, version
	}
	return true, false, version
}

func makeRandString(size int) string {
	buf := make([]byte, size)
	io.ReadFull(rand.Reader, buf)
	return base64.RawURLEncoding.EncodeToString(buf)
}
