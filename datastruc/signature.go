package datastruc

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
)

type PariSign struct {
	R big.Int
	S big.Int
}

func (a *PariSign) Sign(b []byte, prk *ecdsa.PrivateKey) {
	a.R = big.Int{}
	a.S = big.Int{}
	r, s, _ := ecdsa.Sign(rand.Reader, prk, b)
	a.R = *r
	a.S = *s
}

func (a *PariSign) Verify(b []byte, puk *ecdsa.PublicKey) bool {
	return ecdsa.Verify(puk, b, &(a.R), &(a.S))
}


func EncodePrivate(privateKey *ecdsa.PrivateKey) string {
	x509Encoded, _ := x509.MarshalECPrivateKey(privateKey)
	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509Encoded})
	return string(pemEncoded)
}


func EncodePublic(publicKey *ecdsa.PublicKey) string {
	x509EncodedPub, _ := x509.MarshalPKIXPublicKey(publicKey)
	pemEncodedPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509EncodedPub})
	return string(pemEncodedPub)
}



func DecodePrivate(pemEncoded string) *ecdsa.PrivateKey {
	block, _ := pem.Decode([]byte(pemEncoded))
	x509Encoded := block.Bytes
	privateKey, _ := x509.ParseECPrivateKey(x509Encoded)
	return privateKey
}

func DecodePublic(pemEncodedPub string) *ecdsa.PublicKey {
	blockPub, _ := pem.Decode([]byte(pemEncodedPub))
	x509EncodedPub := blockPub.Bytes
	genericPublicKey, _ := x509.ParsePKIXPublicKey(x509EncodedPub)
	publicKey := genericPublicKey.(*ecdsa.PublicKey)
	return publicKey
}

