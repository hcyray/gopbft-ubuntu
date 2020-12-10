package datastruc

import (
	"crypto/ecdsa"
	"crypto/sha256"
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
	jtx.TxHash = sha256.Sum256(jtx.Serialize())

	datatosign := jtx.TxHash
	jtx.Sig.Sign(datatosign[:], prvkey)
	jtx.Pubkey = pubkey
	return jtx
}

func NewLeaveTx(id int, ipaddr string, pubkey string, prvkey *ecdsa.PrivateKey) LeaveTx {
	ltx := LeaveTx{}
	ltx.Id = id
	ltx.IpAddr = ipaddr
	ltx.TxHash = sha256.Sum256(ltx.Serialize())
	datatosign := ltx.TxHash
	ltx.Sig.Sign(datatosign[:], prvkey)
	ltx.Pubkey = pubkey
	return ltx
}

func (jtx *JoinTx) Verify() bool {
	publickey := DecodePublic(jtx.Pubkey)
	datatoverify := jtx.TxHash
	if !jtx.Sig.Verify(datatoverify[:], publickey) {
		return false
	}
	return true
}

func (ltx *LeaveTx) Verify() bool {
	publickey := DecodePublic(ltx.Pubkey)
	datatoverify := ltx.TxHash
	if !ltx.Sig.Verify(datatoverify[:], publickey) {
		return false
	}
	return true
}

//func (jtx *JoinTx) GetHash() [32]byte {
//	return jtx.TxHash
//}
//
//func (ltx *LeaveTx) GetHash() [32]byte {
//	var res [32]byte
//	res = ltx.TxHash
//	return res
//}

func (ltx *LeaveTx) Serialize() []byte {

	var tmp []byte
	EncodeInt(&tmp, ltx.Id)
	EncodeString(&tmp, ltx.IpAddr)
	return tmp
}

func (jtx *JoinTx) Serialize() []byte {

	var tmp []byte
	EncodeInt(&tmp, jtx.Id)
	EncodeString(&tmp, jtx.IpAddr)
	EncodeByteSlice(&tmp, jtx.Measureres.Serialize())
	EncodeByteSlice(&tmp, jtx.InvMeasureres.Serialize())
	return tmp
}

