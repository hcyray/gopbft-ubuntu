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
	txcopy := Transaction{}
	txcopy.Kind = tx.Kind
	txcopy.Timestamp = tx.Timestamp
	txcopy.Source = tx.Source
	txcopy.Recipient = tx.Recipient
	txcopy.Value = tx.Value


	var encoded bytes.Buffer
	gob.Register(elliptic.P256())
	enc := gob.NewEncoder(&encoded)
	err := enc.Encode(txcopy)
	if err != nil {
		log.Panic(err)
	}

	return encoded.Bytes()
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

