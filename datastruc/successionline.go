package datastruc

import (
	"bytes"
	"crypto/sha256"
	"encoding/gob"
	"fmt"
	"log"
)

type SLNode struct {
	Member PeerIdentity
	Next *SLNode
}

type SuccLine struct {
	Tail *SLNode
	CurLeader *SLNode
	Leng int
}

func ConstructSuccessionLine(curConfigure []PeerIdentity) *SuccLine {
	sl := new(SuccLine)
	tmp := []*SLNode{}
	for _, peer := range curConfigure {
		sln := new(SLNode)
		sln.Member = peer
		tmp = append(tmp, sln)
	}
	for i, sln := range tmp {
		if i==len(tmp)-1 {
			sln.Next = tmp[0]
		} else {
			sln.Next = tmp[i+1]
		}
	}
	sl.Tail = tmp[len(tmp)-1]
	sl.CurLeader = sl.Tail.Next
	sl.Leng = len(tmp)
	return sl
}

func (sl *SuccLine) RotateLeader() {
	sl.CurLeader = sl.CurLeader.Next
}

func (sl *SuccLine) InverseRotateLeader() {
	res := FindPrevious(sl, sl.CurLeader)
	sl.CurLeader = res
}

func (sl *SuccLine) DeleteMember(thepeer PeerIdentity) {

}



func (sl *SuccLine) InsertNewSLNode(n1 *SLNode) {
	// insert the new node to the start of the circle chain list
	n1.Next = sl.Tail.Next
	sl.Tail.Next = n1
	sl.Tail = n1
	sl.Leng += 1
}

func FindPrevious(sline *SuccLine, target *SLNode) *SLNode {
	var res *SLNode
	res = sline.Tail
	for {
		if TwoSLNodesEqual(res.Next, target) {
			break
		} else {
			res = res.Next
		}
	}
	return res
}

func TwoSLNodesEqual(n1, n2 *SLNode) bool {
	if n1.Member.PubKey == n2.Member.PubKey {
		return true
	}
	return false
}

func (sl *SuccLine) ConverToList() []PeerIdentity {
	sllist := []PeerIdentity{}
	p := sl.Tail.Next
	for i:=0; i<sl.Leng; i++ {
		sllist = append(sllist, p.Member)
		p = p.Next
	}

	return sllist
}

//func (sl *SuccLine) ConvertToPeerList() []PeerIdentity {
//	sllist := []PeerIdentity{}
//	p := sl.Tail.Next
//	for i:=0; i<sl.Leng; i++ {
//		sllist = append(sllist, p.Member)
//		p = p.Next
//	}
//	return sllist
//}

func (sl *SuccLine) Serialize() []byte {
	// convert the circle chain to a list
	//sllist := []PeerIdentity{}
	//p := sl.Tail.Next
	//for i:=0; i<sl.Leng; i++ {
	//	sllist = append(sllist, p.Member)
	//	p = p.Next
	//}
	sllist := sl.ConverToList()
	var buff bytes.Buffer
	enc := gob.NewEncoder(&buff)
	err := enc.Encode(sllist)
	if err != nil {
		log.Panic(err)
	}
	content := buff.Bytes()
	return content
}

func (sl *SuccLine) GetHash() [32]byte {
	// convert the circle chain to a list
	sllist := []PeerIdentity{}
	p := sl.Tail.Next
	for i:=0; i<sl.Leng; i++ {
		sllist = append(sllist, p.Member)
		p = p.Next
	}

	var buff bytes.Buffer
	enc := gob.NewEncoder(&buff)
	err := enc.Encode(sllist)
	if err != nil {
		log.Panic(err)
	}
	content := buff.Bytes()
	hashval := sha256.Sum256(content)
	return hashval
}

func (sl *SuccLine) Deserialize(conten []byte) {
	var sllist []PeerIdentity
	var buff bytes.Buffer
	buff.Write(conten)
	enc := gob.NewDecoder(&buff)
	err := enc.Decode(&sllist)
	if err != nil {
		log.Panic(err)
	}
	l := len(sllist)

	tmp := []*SLNode{}
	for i:=0; i<l; i++ {
		peer := sllist[i]
		sln := new(SLNode)
		sln.Member = peer
		tmp = append(tmp, sln)
	}

	for i, sln := range tmp {
		if i==len(tmp)-1 {
			sln.Next = tmp[0]
		} else {
			sln.Next = tmp[i+1]
		}
	}
	sl.Tail = tmp[len(tmp)-1]
	sl.Leng = len(tmp)
	sl.CurLeader = sl.Tail.Next
}

func (sl *SuccLine) SucclinePrint() {
	tmpid := make([]int, 0)
	tmppubk := make([]string, 0)
	tmpip := make([]string, 0)
	p := sl.Tail.Next
	for i:=0; i<sl.Leng; i++ {
		tmpid = append(tmpid, p.Member.Id)
		tmppubk = append(tmppubk, p.Member.PubKey)
		tmpip = append(tmpip, p.Member.IpPortAddr)
		p = p.Next
	}
	fmt.Println(tmpid)
	fmt.Println(tmppubk)
}