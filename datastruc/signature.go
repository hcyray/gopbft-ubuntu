package datastruc

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
)

//type PariSign struct {
//	R big.Int
//	S big.Int
//}
//
//func (a *PariSign) Sign(b []byte, prk *ecdsa.PrivateKey) {
//	a.R = big.Int{}
//	a.S = big.Int{}
//	r, s, _ := ecdsa.Sign(rand.Reader, prk, b)
//	a.R = *r
//	a.S = *s
//}
//
//func (a *PariSign) Verify(b []byte, puk *ecdsa.PublicKey) bool {
//	return ecdsa.Verify(puk, b, &(a.R), &(a.S))
//}
type PariSign struct {
	R []byte
	S []byte
}

//func (a *PariSign) ToString() string {
//	s1 := a.R.String()
//	s2 := a.S.String()
//	return s1+s2
//}
//
//func (a *PariSign) ToByteArray() []byte {
//	b1 := a.R.Bytes()
//	b2 := a.S.Bytes()
//	fmt.Println("R bytes:", b1, " length:", len(b1))
//	fmt.Println("S bytes:", b2, " length:", len(b2))
//	b3 := append(b1, b2...)
//	return b3
//}

func (a *PariSign) Sign(b []byte, prk *ecdsa.PrivateKey) {

	r, s, _ := ecdsa.Sign(rand.Reader, prk, b)
	a.R = make([]byte, len(r.Bytes()))
	a.S = make([]byte, len(s.Bytes()))
	copy(a.R, r.Bytes())
	copy(a.S, s.Bytes())
}

func (a *PariSign) Verify(b []byte, puk *ecdsa.PublicKey) bool {
	r := new(big.Int)
	s := new(big.Int)
	r.SetBytes(a.R)
	s.SetBytes(a.S)

	return ecdsa.Verify(puk, b, r, s)
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

