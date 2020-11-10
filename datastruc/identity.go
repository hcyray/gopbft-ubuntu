package datastruc

import (
	"bytes"
	"encoding/gob"
	"log"
)

type PeerIdentity struct {
	PubKey string
	Id int
}

func ConstructConfigure(config *[]PeerIdentity, peerid PeerIdentity) {
	var curconfig []PeerIdentity
	curconfig = *config
	if len(curconfig)==0 {
		*config = append(curconfig, peerid)
	} else {
		// ensure the line is orded
		lenn := len(curconfig)
		var pos int
		var i int
		for i=0; i<lenn; i++ {
			if peerid.Lessthan(curconfig[i]) {
				pos = i
				break
			}
		}
		if i<lenn {
			rear := append([]PeerIdentity{}, curconfig[pos:]...)
			*config = append(append(curconfig[:pos], peerid), rear...)
		} else {
			*config = append(curconfig, peerid)
		}
	}
}

func GenerateNewConfigForJoin(originalpeers []PeerIdentity, jtx JoinTx) []PeerIdentity {
	peers := make([]PeerIdentity, 0)
	for _, v := range originalpeers {
		peers = append(peers, v)
	}
	peers = append(peers, PeerIdentity{jtx.Pubkey, jtx.Id})
	return peers
}

func GenerateNewConfigForLeave(originalpeers []PeerIdentity, ltx LeaveTx) []PeerIdentity {
	res := make([]PeerIdentity, 0)
	i := 0
	for ; i<len(originalpeers); i++ {
		if originalpeers[i].Id==ltx.Id {
			i += 1
			break
		} else {
			res = append(res, originalpeers[i])
		}
	}
	for j:=i; j<len(originalpeers); j++ {
		res = append(res, originalpeers[j])
	}
	return res
}

func ConfigSerialize(config []PeerIdentity) []byte {
	var buff bytes.Buffer
	enc := gob.NewEncoder(&buff)
	err := enc.Encode(config)
	if err != nil {
		log.Panic(err)
	}
	content := buff.Bytes()
	return content
}

func ConfigDeSerialize(content []byte) []PeerIdentity {
	var config []PeerIdentity
	var buff bytes.Buffer
	buff.Write(content)
	dec := gob.NewDecoder(&buff)
	err := dec.Decode(config)
	if err != nil {
		log.Panic(err)
	}
	return config

}

//func (peerid PeerIdentity) Lessthan (peerid2 PeerIdentity) bool {
//	// compare the hash value
//	var p1hash [32]byte
//	var p2hash [32]byte
//	p1hash = sha256.Sum256(peerid.Serialize())
//	p2hash = sha256.Sum256(peerid2.Serialize())
//
//	i:=0
//	for i<32 {
//		if p1hash[i]<p2hash[i] {
//			return true
//		} else if p1hash[i]>p2hash[i] {
//			return false
//		} else {
//			i++
//		}
//	}
//
//	return false
//}

func (peerid PeerIdentity) Lessthan (peerid2 PeerIdentity) bool {
	// compare the hash value
	if peerid.Id<peerid2.Id {
		return true
	}

	return false
}

func (peerid PeerIdentity) Serialize() []byte {
	var encoded bytes.Buffer

	enc := gob.NewEncoder(&encoded)
	err := enc.Encode(peerid)
	if err != nil {
		log.Panic(err)
	}

	return encoded.Bytes()
}