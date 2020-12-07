package datastruc

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/gob"
	"log"
)

type JoinTx struct {
	Id int
	IpAddr string
	TxHash [32]byte

	Measureres MeasurementResultMsg
	InvMeasureres InverseMeasurementResultMsg

	Pubkey string
	Sig PariSign
}

type LeaveTx struct {
	Id int
	IpAddr string
	TxHash [32]byte

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
	jtx.TxHash = sha256.Sum256(jtx.Serial())

	datatosign := jtx.TxHash
	jtx.Sig.Sign(datatosign[:], prvkey)
	jtx.Pubkey = pubkey
	return jtx
}

func NewLeaveTx(id int, ipaddr string, pubkey string, prvkey *ecdsa.PrivateKey) LeaveTx {
	ltx := LeaveTx{}
	ltx.Id = id
	ltx.IpAddr = ipaddr
	ltx.TxHash = sha256.Sum256(ltx.Serial())
	datatosign := ltx.TxHash
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
	return jtx.TxHash
}

func (ltx *LeaveTx) GetHash() [32]byte {
	var res [32]byte

	//lltx := LeaveTx{}
	//lltx.Id = ltx.Id
	//lltx.IpAddr = ltx.IpAddr
	//lltx.TxHash = [32]byte{}
	//lltx.Pubkey = ""
	//lltx.Sig = PariSign{}
	//var buff bytes.Buffer
	//gob.Register(elliptic.P256())
	//enc := gob.NewEncoder(&buff)
	//err := enc.Encode(lltx)
	//if err!=nil {
	//	log.Panic(err)
	//}
	//content := buff.Bytes()
	//res = sha256.Sum256(content)
	res = ltx.TxHash
	return res


	//le := len(content)
	//fmt.Println("leave-tx content has length", le, "content head:", content[0:12], "content tail:", content[le-10:le-1])
	//fmt.Println("leave-tx hash is ", res)
}

func (ltx *LeaveTx) Serial() []byte {

	lltx := LeaveTx{}
	lltx.Id = ltx.Id
	lltx.IpAddr = ltx.IpAddr
	lltx.Pubkey = ""
	lltx.Sig = PariSign{}

	var buff bytes.Buffer
	gob.Register(elliptic.P256())
	enc := gob.NewEncoder(&buff)
	err := enc.Encode(lltx)
	if err!=nil {
		log.Panic(err)
	}
	content := buff.Bytes()
	return content
}

func (jtx *JoinTx) Serial() []byte {
	jjtx := JoinTx{}
	jjtx.Id = jtx.Id
	jjtx.IpAddr = jtx.IpAddr
	jjtx.Pubkey = ""
	jjtx.Sig = PariSign{}
	jjtx.Measureres = jtx.Measureres
	jjtx.InvMeasureres = jtx.InvMeasureres

	var buff bytes.Buffer
	gob.Register(elliptic.P256())
	enc := gob.NewEncoder(&buff)
	err := enc.Encode(jjtx)
	if err!=nil {
		log.Panic(err)
	}
	content := buff.Bytes()
	return content

}