package datastruc

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/gob"
	"log"
	"time"
)

type Transaction struct {
	Kind string
	Timestamp uint64
	//ID   [32]byte
	Source string
	Recipient string
	Value int
	Sig PariSign
}

type TXSet struct {
	Txs []Transaction
}

func (tx *Transaction) GetHash() [32]byte {
	var hash [32]byte
	//txCopy := *tx
	var txCopy Transaction
	txCopy.Kind = tx.Kind
	txCopy.Timestamp = tx.Timestamp
	txCopy.Source = tx.Source
	txCopy.Recipient = tx.Recipient
	txCopy.Value = tx.Value
	//txCopy.ID = [32]byte{}

	hash = sha256.Sum256(txCopy.Serialize())
	return hash
}

func (tx Transaction) Serialize() []byte {
	var encoded bytes.Buffer

	gob.Register(elliptic.P256())
	enc := gob.NewEncoder(&encoded)
	err := enc.Encode(tx)
	if err != nil {
		log.Panic(err)
	}

	return encoded.Bytes()
}

func (tx Transaction) IsMint() bool {
	res := tx.Kind=="mint"
	return res
}

func MintNewTransaction(rannum uint64, pubkeystr string, privkey *ecdsa.PrivateKey) (bool, Transaction) {

	thetimestamp := uint64(time.Now().Unix()) + rannum
	tx := Transaction{"mint", thetimestamp, pubkeystr, pubkeystr, 5, PariSign{}}
	//tx.ID = tx.GetHash()
	tx.Sign(privkey)
	return true, tx
}

func (tx *Transaction) Sign(privkey *ecdsa.PrivateKey) {
	datatosign := tx.GetHash()
	tx.Sig.Sign(datatosign[:], privkey)
}

func (tx *Transaction) Verify() bool {
	if tx.IsMint() {
		publickey := DecodePublic(tx.Source)
		datatoverify := tx.GetHash()
		if !tx.Sig.Verify(datatoverify[:], publickey) {
			return false
		}
		return true
	}
	return true
}

