package goauthpack

import "golang.org/x/crypto/argon2"

func hashpass(data, salt []byte, version int) []byte {
	if version == 0 {
		//argon2 High
		return argon2.IDKey(data, salt, 5, 32*1024, 4, 32)
	}
	return nil
}
