package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVerifyAsymetric(t *testing.T) {
	bodyBytes := []byte("{}")
	hashedBody := sha256.Sum256(bodyBytes)
	encryptedBody := hex.EncodeToString(hashedBody[:])
	encryptedBodyLowerCase := strings.ToLower(encryptedBody)

	timeStamp := "2024-04-22T09:55:40+07:00"

	stringToSign := "POST" + ":" + "/gopay/v1.0/debit/notify" + ":" + encryptedBodyLowerCase + ":" + timeStamp

	signature, err := CreateAsymmetricSignature(stringToSign)
	assert.NoError(t, err)

	err = VerifyAsymmetricSignature(stringToSign, signature)
	assert.NoError(t, err)
}

func CreateAsymmetricSignature(message string) (string, error) {
	privBlock, _ := pem.Decode([]byte(privateKey))
	key, err := x509.ParsePKCS8PrivateKey(privBlock.Bytes)
	if err != nil {
		return "", err
	}

	hashedMessage := sha256.Sum256([]byte(message))
	signature, _ := rsa.SignPKCS1v15(rand.Reader, key.(*rsa.PrivateKey), crypto.SHA256, hashedMessage[:])
	base64String := base64.StdEncoding.EncodeToString(signature)
	return base64String, nil
}

func VerifyAsymmetricSignature(message string, signature string) error {
	pubBlock, _ := pem.Decode([]byte(publicKey))
	if pubBlock == nil {
		return errors.New("failed to parse public key")
	}

	key, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
	if err != nil {
		return err
	}

	rsaKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return errors.New("public key is not RSA")
	}

	hashedMessage := sha256.Sum256([]byte(message))
	signatureBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return err
	}

	return rsa.VerifyPKCS1v15(rsaKey, crypto.SHA256, hashedMessage[:], signatureBytes)
}

const privateKey = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC9iWOfXKUnT/F7
g6bnxPEfxCnV0rhBajukTfe57fcum8+wRaktyhTPuOivI2rpmkbawJBtGUy7vkg9
KcrAUBjxL/xbZ1L25MQNxTozIDYxpzJUF3kv2o3MEDDpNGRC/GGzM85q2O2DR9KZ
BidUb/zetolH+fT0ggxIXT2k9+256ke0FYE5+HdwvYmo0y+6O3lCVcR+o7KDjW1t
YSjxDhHh8fFu5xOupK6B5eGuKrOHLcidDmRfBwaGOh0wBAQOcrySFU7Lj3MMTCD6
dgQ8K0p0TnZZray+p/TFdp6V5r1fbNacANaE1Ap4KLe1mS2u+J/2coXdrZB7vTa4
KxFz79bxAgMBAAECggEBAKs7nE01Hd/OUZQM9JUfT9grGMCchupSV1+xMMVBP7dT
/OZ7iMRddT/VBiJ0FPrG7oxivBhUawaSeiEHyKzFsEL13z+UsVdshdMLA/F8gHmL
W+Ss8EdTZBef6RBGzO3XpUyI2Uuef7XDBXhKHu4h3oo2zv+/ypW7h+04j6CifJsg
hY2XToArxUArG5ZYZF8qsRRc8gL/V0u/ArCxlOeHWwi/nj8m2AQnTEYIFWkamsRS
t09WaBuZuxOEISjUFdAfZoNe7p4iE+KDjfnwDYG1asGnnntMKqt60o1J5JrGZ4oV
5TQ2Uk1wYCVJMVR/HLN2HGSlEmovbrthKTQkd3HEIgECgYEA8t9/sFej3BB/M4UX
rCxkZK6qjbDIZLt6zWG7JvQxJHYMoLSI8imB0P3Gt1gqgZpGmwbaZtkd1lw1KWx4
VEDTXT6gXgPoeZsVVxzSxoxsOQp3l5T6mTo4UfnIK5YwIewFDvSC5namsGDUH5Lc
eZZqE69QxzOY1PFt4zHsVnMD+7kCgYEAx8fnf+lOzpYq6lEHL1RbEw8YHDRo8Ixg
vGkXitIXaGw67gOA3OF1q/XVpZv54gb+ph+sXZrvAUWo/fJJ3jRmuFBa0Qn+Idum
TegF7awi6OmjicSwJRctZ5yes96QKvZW3lYNUcFx9ES9wO1c6zicCeWDQgFpnL46
1Eec3mWQAPkCgYBJM9X/p5qq1IoSVDYbXdHwiri7NiJgQiW0S5WmGwnIzI/nzCJO
ovYOsL65OiitoXtQdJNVVnFoz6fyUVA/TL6oJx0c2R6zsGuRMw3QbDieRKphFLUn
g+W/x4JuqLjfMI0hwc7GedKp7LViwtgTCaP1RO0a7VFONWqChOSP9eCoeQKBgE6w
ARGTflPGN+8ErTTKH/kYx+FMD003rV5ocjpeV5PslSVsQdQ+BVAOyvCox7psEN6z
uPtBbAPvQQmM5eVcdF0CYVLWgb8qOY2T5snfM/zTEXPRAaQKRfr6aFPmRJh3YG3A
LQzXiZ+xd5/GngOTz3niaVmVHtj64Eb+Ud4S2K5ZAoGBAIiV4j7zLHrYzICN3gVI
uGWNRwClmyCDpXGnwz2PkOS6PuCLOMthxhPEPiPGE/iYwjf3SPz9cUS9h8ZhXbFp
QvVftfM9Snb67cweWCZFSm6e8swgHqSwUd4/HwadWzy1wcysEaxA9RiVFatJbVxn
1FomEBfapBDebLtufYiNoEWX
-----END PRIVATE KEY-----
`

const publicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvYljn1ylJ0/xe4Om58Tx
H8Qp1dK4QWo7pE33ue33LpvPsEWpLcoUz7joryNq6ZpG2sCQbRlMu75IPSnKwFAY
8S/8W2dS9uTEDcU6MyA2MacyVBd5L9qNzBAw6TRkQvxhszPOatjtg0fSmQYnVG/8
3raJR/n09IIMSF09pPftuepHtBWBOfh3cL2JqNMvujt5QlXEfqOyg41tbWEo8Q4R
4fHxbucTrqSugeXhriqzhy3InQ5kXwcGhjodMAQEDnK8khVOy49zDEwg+nYEPCtK
dE52Wa2svqf0xXaelea9X2zWnADWhNQKeCi3tZktrvif9nKF3a2Qe702uCsRc+/W
8QIDAQAB
-----END PUBLIC KEY-----
`
