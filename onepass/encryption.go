package onepass

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/sha1"

	"golang.org/x/crypto/pbkdf2"
)

var (
	saltPrefix = []byte("Salted__")
	saltEmpty  = make([]byte, 16)
)

type salted []byte

func (s salted) Salt() []byte {
	if bytes.HasPrefix(s, saltPrefix) {
		return s[8:16]
	}

	return saltEmpty
}

func (s salted) Bytes() []byte {
	if bytes.HasPrefix(s, saltPrefix) {
		return s[16:]
	}

	return s
}

func unpadPKCS7(src []byte) []byte {
	pad := int(src[len(src)-1])
	if pad >= 16 {
		return src
	}

	return src[:len(src)-pad]
}

func PBKDF2(password, salt []byte, iter int) []byte {
	k := pbkdf2.Key(password, salt, iter, 32, sha1.New)
	return k
}

func decrypt(key, iv, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	plaintext := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ciphertext)

	plaintext = unpadPKCS7(plaintext)

	return plaintext, nil
}

func deriveOpenSSL(key, salt []byte) (aesKey, aesIv []byte) {
	// 128bit_Key = MD5(Passphrase + Salt)
	// 256bit_Key = 128bit_Key + MD5(128bit_Key + Passphrase + Salt)

	key = key[:len(key)-16]

	b := append(key, salt...)
	m := md5.Sum(b)
	aesKey = append(aesKey, m[:]...)

	b = append(aesKey, key...)
	b = append(b, salt...)
	m = md5.Sum(b)
	aesKey = append(aesKey, m[:]...)

	aesIv = aesKey[16:]
	aesKey = aesKey[:16]

	return
}
