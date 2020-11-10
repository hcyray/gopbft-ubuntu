package datastruc

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/gob"
	"fmt"
)


type ProposeTestMsg struct {
	Challange uint64

	InitialBalance map[string]int
	TxBatch []Transaction // there is some wrong signature, and some unvalid tx without enough balance

	IpAddr string
	Round int
	Tester int

	Pubkey string
	Sig PariSign
}

type ProposeResponseWoValidateMsg struct {
	Challange uint64

	Round int
	Testee int
	TxBatch []Transaction

	Pubkey string
	Sig PariSign
}

type ProposeResponseWithValidateMsg struct {
	Challange uint64

	TxBatch []Transaction
	ValidateResult []bool // indicate the xth tx is valid

	Round int
	Testee int

	Pubkey string
	Sig PariSign
}

type WriteTestMsg struct {
	Challange uint64

	IpAddr string
	Round int
	Tester int

	Pubkey string
	Sig PariSign
}

type WriteResponseMsg struct {
	Challange uint64

	Round int
	Testee int

	Pubkey string
	Sig PariSign
}

type MeasurementResultMsg struct {
	Id int
	Round int
	Peers []int
	ProposeDealy map[int]int
	ValidateDelay map[int]int
	WriteDelay map[int]int

	ProposeFlag bool

	Pubkey string
	Sig PariSign
}

type InverseMeasurementResultMsg struct {
	Id int
	Round int
	Peers []int
	ProposeDealy map[int]int
	WriteDelay map[int]int
	ValidateDelay map[int]int

	Pubkey string
	Sig PariSign
}

type SingleMeasurementAToB struct {
	Tester int
	Testee int

	Proposedelay int
	Validatedelay int
	Writedelay int

	Pubkey string
	Sig PariSign
}

type RequestTestMsg struct {
	Testee int
	IpAddr string

	Pubkey string
	Sig PariSign
}




func NewProposeMsg(tester int, roud int, ip string, txlist []Transaction, rann uint64) ProposeTestMsg {
	ppmsg := ProposeTestMsg{}

	ppmsg.Challange = rann
	ppmsg.InitialBalance = make(map[string]int)
	ppmsg.TxBatch = txlist

	ppmsg.IpAddr = ip
	ppmsg.Round = roud
	ppmsg.Tester = tester

	// todo add signature
	return ppmsg
}

func NewWriteMsg(tester int, roud int, ip string, rann uint64) WriteTestMsg {
	wrmsg := WriteTestMsg{}

	wrmsg.Challange = rann
	wrmsg.Round = roud
	wrmsg.Tester = tester
	wrmsg.IpAddr = ip

	// todo add signature
	return wrmsg
}

func NewProposeResponseWoValidateMsg(id int, round int, challeng uint64, txbatch []Transaction) ProposeResponseWoValidateMsg {
	// todo, validation result omitted currently
	pprmsg := ProposeResponseWoValidateMsg{}

	pprmsg.Challange = challeng
	pprmsg.TxBatch = txbatch
	pprmsg.Round = round
	pprmsg.Testee = id

	return pprmsg
}

func NewProposeResponseWithValidateMsg(id int, round int, challeng uint64, reslist []bool, txbatch []Transaction) ProposeResponseWithValidateMsg {
	// todo, validation result omitted currently
	pprmsg := ProposeResponseWithValidateMsg{}

	pprmsg.Challange = challeng
	pprmsg.TxBatch = txbatch
	pprmsg.Round = round
	pprmsg.Testee = id
	pprmsg.ValidateResult = make([]bool, len(reslist))

	return pprmsg
}

func NewWriteResponseMsg(id int, round int, challeng uint64) WriteResponseMsg {
	wrrmsg := WriteResponseMsg{}

	wrrmsg.Challange = challeng
	wrrmsg.Round = round
	wrrmsg.Testee = id
	return wrrmsg
}

func NewMeasurementResultMsg(id int, round int, peers []int, proposeres map[int]int, writeres map[int]int,
	validateres map[int]int, proposeflag bool, pubkeystr string, privkey *ecdsa.PrivateKey) MeasurementResultMsg {
	mrmsg := MeasurementResultMsg{}

	mrmsg.Id = id
	mrmsg.Round = round
	for _, v := range peers {
		mrmsg.Peers = append(mrmsg.Peers, v)
	}
	mrmsg.ProposeDealy = proposeres
	mrmsg.WriteDelay = writeres
	mrmsg.ValidateDelay = validateres
	mrmsg.ProposeFlag = proposeflag

	// todo, add signature

	return mrmsg
}

func NewInverseMeasurementResultMsg(id int, round int, peers []int, proposeres map[int]int, writeres map[int]int,
	validateres map[int]int, pubkeystr string, privkey *ecdsa.PrivateKey) InverseMeasurementResultMsg {
	imrmsg := InverseMeasurementResultMsg{}

	imrmsg.Id = id
	imrmsg.Round = round
	for _, v := range peers {
		imrmsg.Peers = append(imrmsg.Peers, v)
	}
	imrmsg.ProposeDealy = proposeres
	imrmsg.WriteDelay = writeres
	imrmsg.ValidateDelay = validateres

	// todo, add signature

	return imrmsg
}

func NewRequestTestMsg(id int, ip string) RequestTestMsg {
	reqtestmsg := RequestTestMsg{}

	reqtestmsg.Testee = id
	reqtestmsg.IpAddr = ip
	return reqtestmsg
}

func NewSingleMeasurement(a, b int, delays []int, pubkey string, prvkey *ecdsa.PrivateKey) SingleMeasurementAToB {
	smmsg := SingleMeasurementAToB{}

	smmsg.Tester = a
	smmsg.Testee = b
	smmsg.Proposedelay = delays[0]
	smmsg.Validatedelay = delays[1]
	smmsg.Writedelay = delays[2]

	// todo, add signature

	return smmsg
}

func (pp *ProposeTestMsg) Deserialize(content []byte) {
	var buff bytes.Buffer
	buff.Write(content)
	dec := gob.NewDecoder(&buff)
	err := dec.Decode(pp)
	if err != nil {
		fmt.Println("propose decoding error")
	}
}

func (ppr *ProposeResponseWoValidateMsg) Deserialize(content []byte) {
	var buff bytes.Buffer
	buff.Write(content)
	dec := gob.NewDecoder(&buff)
	err := dec.Decode(ppr)
	if err != nil {
		fmt.Println("propose-response decoding error")
	}
}

func (ppr *ProposeResponseWithValidateMsg) Deserialize(content []byte) {
	var buff bytes.Buffer
	buff.Write(content)
	dec := gob.NewDecoder(&buff)
	err := dec.Decode(ppr)
	if err != nil {
		fmt.Println("propose-response decoding error")
	}
}

func (wr *WriteTestMsg) Deserialize(content []byte) {
	var buff bytes.Buffer
	buff.Write(content)
	dec := gob.NewDecoder(&buff)
	err := dec.Decode(wr)
	if err != nil {
		fmt.Println("write decoding error")
	}
}

func (wrr *WriteResponseMsg) Deserialize(content []byte) {
	var buff bytes.Buffer
	buff.Write(content)
	dec := gob.NewDecoder(&buff)
	err := dec.Decode(wrr)
	if err != nil {
		fmt.Println("write-response decoding error")
	}
}

func (mr *MeasurementResultMsg) GetHash() [32]byte {
	rawdata := []byte(string(mr.Id) + "measurement result" + string(mr.Round))
	res := sha256.Sum256(rawdata)
	return res
}

func PeersMatch(alist []int, blist []int) bool {
	res := true
	if len(alist)!=len(blist) {
		res = false
	} else {
		for i:=0; i<len(alist); i++ {
			if alist[i]!=blist[i] {
				res = false
			}
		}
	}
	return res
}