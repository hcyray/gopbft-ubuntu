package datastruc

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/gob"
	"fmt"
	"log"
)


type Block struct {
	// the block head
	Blockhead BlockHead
	PubKey string
	Sig PariSign

	// the block body
	TransactionList []Transaction
	MeasurementResList []MeasurementResultMsg
	JoinTxList []JoinTx
	LeaveTxList []LeaveTx
	Configure []PeerIdentity
}

type BlockHead struct {
	CreatorId int
	Kind string
	Ver int
	Height int
	HeadHash [32]byte

	PrevHash [32]byte
	//SystemHash [32]byte
	TXMerkleTreeHash [32]byte
}

func NewTxBlock(id int, pubkeystr string, prvkey *ecdsa.PrivateKey, txpool *[]Transaction, measureinfolist []MeasurementResultMsg,
	height int, ver int, prevhash [32]byte) Block {
	bloc := Block{}
	bloc.Blockhead.CreatorId = id
	bloc.Blockhead.Kind = "txblock"
	bloc.Blockhead.Ver = ver
	bloc.Blockhead.Height = height

	bloc.Blockhead.PrevHash = prevhash
	//bloc.Blockhead.SystemHash = syshash

	bloc.TransactionList = make([]Transaction, 0)
	bloc.TransactionList = *txpool
	bloc.MeasurementResList = measureinfolist
	//bloc.fetchTransactionForBlock(txpool)

	err := GenTxMerkTree(&bloc.TransactionList, &bloc.Blockhead.TXMerkleTreeHash)
	if err != nil {
		fmt.Println("error in generating merkle tree")
	}

	bloc.Blockhead.HeadHash = sha256.Sum256(bloc.Blockhead.Serialize())
	datatosign := bloc.GetHash()
	bloc.Sig.Sign(datatosign[:], prvkey)
	bloc.PubKey = pubkeystr

	fmt.Println("the tx number of the new packed block at height", height, "is ", len(bloc.TransactionList))
	return bloc
}

func NewJoinConfigBlock(pubkeystr string, prvkey *ecdsa.PrivateKey, jtx JoinTx, peers []PeerIdentity, height int, ver int, prevhash [32]byte, syshash [32]byte) Block {
	bloc := Block{}
	bloc.Blockhead.Kind = "configblock"
	bloc.Blockhead.Ver = ver
	bloc.Blockhead.Height = height
	bloc.Blockhead.PrevHash = prevhash
	//bloc.Blockhead.SystemHash = syshash

	bloc.TransactionList = make([]Transaction, 0)
	bloc.JoinTxList = append(bloc.JoinTxList, jtx)
	bloc.LeaveTxList = make([]LeaveTx, 0)
	bloc.Configure = peers

	bloc.Blockhead.HeadHash = sha256.Sum256(bloc.Blockhead.Serialize())
	datatosign := bloc.GetHash()
	bloc.Sig.Sign(datatosign[:], prvkey)
	bloc.PubKey = pubkeystr

	return bloc
}

func NewLeaveConfigBlock(pubkeystr string, prvkey *ecdsa.PrivateKey, ltx LeaveTx, peers []PeerIdentity, height int, ver int, prevhash [32]byte) Block {
	bloc := Block{}
	bloc.Blockhead.Kind = "configblock"
	bloc.Blockhead.Ver = ver
	bloc.Blockhead.Height = height
	bloc.Blockhead.PrevHash = prevhash
	//bloc.Blockhead.SystemHash = syshash

	bloc.TransactionList = make([]Transaction, 0)
	bloc.JoinTxList = make([]JoinTx, 0)
	bloc.LeaveTxList = append(bloc.LeaveTxList, ltx)
	bloc.Configure = peers

	bloc.Blockhead.HeadHash = sha256.Sum256(bloc.Blockhead.Serialize())
	datatosign := bloc.GetHash()
	bloc.Sig.Sign(datatosign[:], prvkey)
	bloc.PubKey = pubkeystr

	return bloc
}

func ConstructGenesisBlock(config []PeerIdentity) Block {
	geneb := Block{}
	geneb.Blockhead.Kind = "geblock"
	geneb.Blockhead.Ver = 0
	geneb.Blockhead.Height = 0
	geneb.Blockhead.PrevHash = [32]byte{}
	//geneb.Blockhead.SystemHash = syshash
	geneb.TransactionList = []Transaction{}
	err := GenTxMerkTree(&geneb.TransactionList, &geneb.Blockhead.TXMerkleTreeHash)
	if err != nil {
		fmt.Println("error in generating merkle tree")
	}

	geneb.Sig = PariSign{} // genesis block has no creator, thus no signature
	geneb.PubKey = "" // genesis block has no creator, thus no public key
	return geneb
}

func (block *Block) fetchTransactionForBlock(txpool *[]Transaction) {
	res := []Transaction{}
	for i:=0; i<len(*txpool); i++ {
		if i<len(*txpool) {
			res = append(res, (*txpool)[i])
		} else {
			break
		}
	}
	block.TransactionList = res
}

func (block *Block) IncludeTheTx(thetx *Transaction) bool {
	for _, tx := range block.TransactionList {
		if TwoHashEqual(thetx.GetHash(), tx.GetHash()) {
			return true
		}
	}
	return false
}

func (block *Block) GetSerialize() []byte {
	var buff bytes.Buffer
	enc := gob.NewEncoder(&buff)
	err := enc.Encode(block)
	if err != nil {
		log.Panic(err)
	}
	content := buff.Bytes()
	return content
}

func (blockhead *BlockHead) Serialize() []byte {
	var buff bytes.Buffer
	enc := gob.NewEncoder(&buff)
	err := enc.Encode(blockhead)
	if err != nil {
		log.Panic(err)
	}
	content := buff.Bytes()
	return content
}


func GenTxMerkTree(d *[]Transaction, out *[32]byte) error {
	if len(*d) == 0 {
		return nil
	}
	if len(*d) == 1 {
		id := (*d)[0].GetHash()
		tmp := id[:]
		SingleHash256(&tmp, out)
	} else {
		l := len(*d)
		d1 := (*d)[:l/2]
		d2 := (*d)[l/2:]
		var out1, out2 [32]byte
		GenTxMerkTree(&d1, &out1)
		GenTxMerkTree(&d2, &out2)
		tmp := append(out1[:], out2[:]...)
		SingleHash256(&tmp, out)
	}
	return nil
}

func (bloc *Block) GetHash() [32]byte {
	//var hash [32]byte
	//data := bloc.Blockhead.GetSerialize()
	//hash = sha256.Sum256(data)
	//return hash
	return bloc.Blockhead.HeadHash
}



