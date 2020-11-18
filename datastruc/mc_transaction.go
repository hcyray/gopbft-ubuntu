package datastruc

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/gob"
	"fmt"
	"log"
)

type JoinTx struct {
	Id int
	IpAddr string
	Pubkey string

	Measureres MeasurementResultMsg
	InvMeasureres InverseMeasurementResultMsg

	Sig PariSign
}

type LeaveTx struct {
	Id int
	IpAddr string
	Pubkey string

	Sig PariSign
}

type JLTxSet struct {
	JTxset []JoinTx
	LTxSet []LeaveTx
}

func NewJoinTx(id int, ipaddr string, mr MeasurementResultMsg, imr InverseMeasurementResultMsg, pubkey string,
	prvkey *ecdsa.PrivateKey) JoinTx {
	jtx := JoinTx{}
	jtx.Id = id
	jtx.IpAddr = ipaddr
	jtx.Measureres = mr
	jtx.InvMeasureres = imr
	jtx.Pubkey = pubkey

	datatosign := jtx.GetHash()
	jtx.Sig.Sign(datatosign[:], prvkey)
	return jtx
}

func NewLeaveTx(id int, ipaddr string, pubkey string, prvkey *ecdsa.PrivateKey) LeaveTx {
	ltx := LeaveTx{}
	ltx.Id = id
	ltx.IpAddr = ipaddr

	datatosign := ltx.GetHash()
	ltx.Sig.Sign(datatosign[:], prvkey)
	ltx.Pubkey = pubkey
	return ltx
}

func (jtx *JoinTx) Verify() bool {
	publickey := DecodePublic(jtx.Pubkey)
	datatoverify := jtx.GetHash()
	if !jtx.Sig.Verify(datatoverify[:], publickey) {
		return false
	}
	return true
}

func (ltx *LeaveTx) Verify() bool {
	publickey := DecodePublic(ltx.Pubkey)
	datatoverify := ltx.GetHash()
	if !ltx.Sig.Verify(datatoverify[:], publickey) {
		return false
	}
	return true
}

func (jtx *JoinTx) GetHash() [32]byte {
	var res [32]byte

	jjtx := JoinTx{}
	jjtx.Id = jtx.Id
	jjtx.Pubkey = jtx.Pubkey
	jjtx.IpAddr = jtx.IpAddr

	var buff bytes.Buffer
	enc := gob.NewEncoder(&buff)
	err := enc.Encode(jjtx)
	if err!=nil {
		log.Panic(err)
	}
	content := buff.Bytes()
	res = sha256.Sum256(content)

	return res
}

func (ltx *LeaveTx) GetHash() [32]byte {
	var res [32]byte

	lltx := LeaveTx{}
	lltx.Id = ltx.Id
	lltx.IpAddr = ltx.IpAddr

	var buff bytes.Buffer
	enc := gob.NewEncoder(&buff)
	err := enc.Encode(lltx)
	if err!=nil {
		log.Panic(err)
	}
	content := buff.Bytes()
	le := len(content)
	fmt.Println("leave-tx content has length", le, "content head:", content[0:12], "content tail:", content[le-10:le-1])
	res = sha256.Sum256(content)
	fmt.Println("leave-tx hash is ", res)

	return res
}