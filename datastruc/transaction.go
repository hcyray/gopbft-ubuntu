package datastruc

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"time"
)

type Transaction struct {
	Kind string
	Timestamp uint64
	Source string
	Recipient string
	Value int
	TxHash [32]byte
	Sig PariSign
}

type TXSet struct {
	Txs []Transaction
}

func (tx *Transaction) GetHash() [32]byte {
	return tx.TxHash
}

func (tx *Transaction) Serialize() []byte {
	var tmp []byte

	EncodeString(&tmp, tx.Kind)
	EncodeUint64(&tmp, tx.Timestamp)
	EncodeString(&tmp, tx.Source)
	EncodeString(&tmp, tx.Recipient)
	EncodeInt(&tmp, tx.Value)

	return tmp
}

func (tx Transaction) IsMint() bool {
	res := tx.Kind=="mint"
	return res
}

func MintNewTransaction(rannum uint64, accountstr string, privkey *ecdsa.PrivateKey) (bool, Transaction) {

	thetimestamp := uint64(time.Now().Unix()) + rannum
	tx := Transaction{}
	tx.Kind = "mint"
	tx.Timestamp = thetimestamp
	tx.Source = accountstr
	tx.Recipient = accountstr
	tx.Value = 5
	tx.TxHash = sha256.Sum256(tx.Serialize())

	//tx.ID = tx.GetHash()
	tx.Sign(privkey)
	return true, tx
}

func (tx *Transaction) Sign(privkey *ecdsa.PrivateKey) {
	datatosign := tx.GetHash()
	tx.Sig.Sign(datatosign[:], privkey)
}

func (tx *Transaction) Verify(pukstr string) bool {
	if tx.IsMint() {
		publickey := DecodePublic(pukstr)
		datatoverify := tx.GetHash()
		if !tx.Sig.Verify(datatoverify[:], publickey) {
			return false
		}
		return true
	}
	return true
}

