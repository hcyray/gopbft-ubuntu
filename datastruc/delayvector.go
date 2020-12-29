package datastruc

import (
	"bytes"
	"crypto/elliptic"
	"encoding/gob"
	"fmt"
	"log"
	"time"
)

func (cdedata *CDEdata) CreateDelayVector(txbatch []Transaction) *DelayVector {
	dv := &DelayVector{}

	dv.Tester = cdedata.Id
	dv.IpAddr = cdedata.IpAddr
	dv.Round = cdedata.Round
	dv.Peers = cdedata.Peers
	dv.Peerexceptme = []int{}
	for _, id := range dv.Peers {
		if id!=dv.Tester {
			dv.Peerexceptme = append(dv.Peerexceptme, id)
		}
	}

	dv.ProposeDelaydata = make(map[int]int)
	dv.WriteDelaydata = make(map[int]int)
	dv.ValidationDelaydata = make(map[int]int)
	dv.HashDelaydata = make(map[int]int)
	for _, v := range dv.Peers {
		dv.ProposeDelaydata[v] = MAXWAITTIME // initialize to be the maximum value
		dv.WriteDelaydata[v] = MAXWAITTIME
		dv.ValidationDelaydata[v] = MAXWAITTIME
		dv.HashDelaydata[v] = MAXWAITTIME
	}
	dv.Txbatch = txbatch
	dv.SendCh = cdedata.SendCh
	dv.BroadcastCh = cdedata.BroadcastCh
	dv.RecvProposeResponWoCh = cdedata.RecvProposeResponWoCh
	dv.RecvProposeResponWCh = cdedata.RecvProposeResponWCh
	dv.RecvWriteResponWoCh = cdedata.RecvWriteResponWoCh
	dv.RecvWriteResponWCh = cdedata.RecvWriteResponWCh
	dv.RecvProposeResponWoFromOldCh = cdedata.RecvProposeResponWoFromOldCh
	dv.RecvProposeResponWFromOldCh = cdedata.RecvProposeResponWFromOldCh
	dv.RecvWriteResponWoFromOldCh = cdedata.RecvWriteResponWoFromOldCh
	dv.RecvWriteResponWFromOldCh = cdedata.RecvWriteResponWFromOldCh

	dv.RecvProposeResponWoFromNewCh = cdedata.RecvProposeResponWoFromNewCh
	dv.RecvProposeResponWFromNewCh = cdedata.RecvProposeResponWFromNewCh
	dv.RecvWriteResponWoFromNewCh = cdedata.RecvWriteResponWoFromNewCh
	dv.RecvWriteResponWFromNewCh = cdedata.RecvWriteResponWFromNewCh
	return dv
}

type DelayVector struct
{
	Round int
	Tester int
	IpAddr string
	Peers []int
	Peerexceptme []int

	ProposeDelaydata map[int]int
	ValidationDelaydata map[int]int
	WriteDelaydata map[int]int
	HashDelaydata map[int]int

	Txbatch []Transaction
	SendCh chan DatatosendWithIp
	BroadcastCh chan Datatosend

	RecvProposeResponWoCh chan DataReceived
	RecvProposeResponWCh chan DataReceived
	RecvWriteResponWoCh chan DataReceived
	RecvWriteResponWCh chan DataReceived

	RecvProposeResponWoFromOldCh chan DataReceived
	RecvProposeResponWFromOldCh chan DataReceived
	RecvWriteResponWoFromOldCh chan DataReceived
	RecvWriteResponWFromOldCh chan DataReceived

	RecvProposeResponWoFromNewCh chan DataReceived
	RecvProposeResponWFromNewCh chan DataReceived
	RecvWriteResponWoFromNewCh chan DataReceived
	RecvWriteResponWFromNewCh chan DataReceived
}

func (delayv *DelayVector) UpdateWrite() {
	// this func blocks when executing

	// send and write
	rann := uint64(time.Now().Unix())
	wrmsg := NewWriteMsg(delayv.Tester, delayv.Round, delayv.IpAddr, rann)
	var buff bytes.Buffer
	gob.Register(elliptic.P256())
	enc := gob.NewEncoder(&buff)
	err := enc.Encode(wrmsg)
	if err != nil {
		log.Panic(err)
	}
	content := buff.Bytes()
	datatosend := Datatosend{delayv.Peerexceptme, "writetest", content}
	delayv.BroadcastCh <- datatosend

	starttime := time.Now()
	for _,v:=range delayv.Peers {
		delayv.WriteDelaydata[v] = MAXWAITTIME
		delayv.HashDelaydata[v] = MAXWAITTIME
	}
	delayv.WriteDelaydata[delayv.Tester] = 0
	delayv.HashDelaydata[delayv.Tester] = 0
	thetimer := time.NewTimer(time.Millisecond*MAXWAITTIME)
	t1 := make(map[int]int)
	for _, v := range delayv.Peers {
		t1[v] = 0
	}
theloop:
	for {
		select {
		case <-thetimer.C:
			break theloop
		case theresponse :=<- delayv.RecvWriteResponWoCh:
			var wrr WriteResponseWoValidateMsg // decode response
			wrr.Deserialize(theresponse.Msg)
			// check correctness
			if delayv.Round==wrr.Round {
				t1[wrr.Testee] = int(time.Since(starttime).Milliseconds())
				delayv.WriteDelaydata[wrr.Testee] = t1[wrr.Testee]/2
				// check if all delay data is updated
				if AllUpdated(delayv.WriteDelaydata, delayv.HashDelaydata, MAXWAITTIME) {
					break theloop
				}
			} else {
				fmt.Println("the received write-response round number not matchs, current round:", delayv.Round, "response round:", wrr.Round)
			}
		case theresponse :=<- delayv.RecvWriteResponWCh:
			var wrr WriteResponseWithValidateMsg // decode response
			wrr.Deserialize(theresponse.Msg)
			// check correctness
			if delayv.Round==wrr.Round {
				delayv.HashDelaydata[wrr.Testee] = int(time.Since(starttime).Milliseconds()) - t1[wrr.Testee]
				// check if all delay data is updated
				if AllUpdated(delayv.WriteDelaydata, delayv.HashDelaydata, MAXWAITTIME) {
					break theloop
				}
			} else {
				fmt.Println("the received write-response round number not matchs, current round:", delayv.Round, "response round:", wrr.Round)
			}
		}
	}
}

func (delayv *DelayVector) UpdatePropose() {
	// this func blocks when executing, this func tends to overestimate propose
	// delay, but it's ok for consensus delay estimation

	// send propose
	rann := uint64(time.Now().Unix())
	ppmsg := NewProposeMsg(delayv.Tester, delayv.Round, delayv.IpAddr, delayv.Txbatch, rann)
	starttime := time.Now()

	var buff bytes.Buffer
	gob.Register(elliptic.P256())
	enc := gob.NewEncoder(&buff)
	err := enc.Encode(ppmsg)
	if err != nil {
		log.Panic(err)
	}
	content := buff.Bytes()
	datatosend := Datatosend{delayv.Peerexceptme, "proposetest", content}
	delayv.BroadcastCh <- datatosend // question, hope this won't block or take too much time

	// wait for reponse
	//gotresponse := make(map[int]bool)
	//for _, v := range delayv.Peers {
	//	gotresponse[v] = false
	//}
	for _,v:=range delayv.Peers {
		delayv.ProposeDelaydata[v] = MAXWAITTIME
		delayv.ValidationDelaydata[v] = MAXWAITTIME
	}
	delayv.ProposeDelaydata[delayv.Tester] = 0
	delayv.ValidationDelaydata[delayv.Tester] = 0
	thetimer := time.NewTimer(time.Millisecond*MAXWAITTIME)
	t1 := make(map[int]int)
	for _, v := range delayv.Peers {
		t1[v] = 0
	}
	//fmt.Println("instance", delayv.Tester, "waiting for propose-reply...")
theloop:
	for {
		select {
		case <-thetimer.C:
			//fmt.Println("instance", delayv.Tester, "update propose timer expires, exits")
			break theloop
		case theresponse :=<- delayv.RecvProposeResponWoCh:
			//fmt.Println("instance", delayv.Tester, "delay vector receives a propose-response-wo signal")
			// decode response
			var ppr ProposeResponseWoValidateMsg
			ppr.Deserialize(theresponse.Msg)
			// todo, check correctness
			if ppr.Round==delayv.Round && ppr.Challange==rann {
				// update delay vector
				t1[ppr.Testee] = int(time.Since(starttime).Milliseconds())
				// tend to overestimate propose-delay
				delayv.ProposeDelaydata[ppr.Testee] = t1[ppr.Testee] / 2
				// check if all items updated, if so, exit
				if AllUpdated(delayv.ProposeDelaydata, delayv.ValidationDelaydata, MAXWAITTIME) {
					break theloop
				}
			} else {
				fmt.Println("the received propose-response-wo round number not match, current round:", delayv.Round, "response round:", ppr.Round)
			}
		case theresponse :=<- delayv.RecvProposeResponWCh:
			var ppr ProposeResponseWithValidateMsg
			ppr.Deserialize(theresponse.Msg)
			if ppr.Round==delayv.Round {
				// update delay vector
				delayv.ValidationDelaydata[ppr.Testee] = int(time.Since(starttime).Milliseconds()) - t1[ppr.Testee]
				// check if all items updated, if so, exit
				if AllUpdated(delayv.ProposeDelaydata, delayv.ValidationDelaydata, MAXWAITTIME) {
					break theloop
				}
			}
		}
	}
}



func (delayv *DelayVector) UpdateWriteAtNew() {
	rann := uint64(time.Now().Unix())
	wrmsg := NewWriteMsg(delayv.Tester, delayv.Round, delayv.IpAddr, rann)
	var buff bytes.Buffer
	gob.Register(elliptic.P256())
	enc := gob.NewEncoder(&buff)
	err := enc.Encode(wrmsg)
	if err != nil {
		log.Panic(err)
	}
	content := buff.Bytes()
	fmt.Println("new instance invoke update-write-at-new, peers:", delayv.Peers, "its own id:", delayv.Tester, "write-msg:", wrmsg)
	datatosend := Datatosend{delayv.Peers, "writetestfromnew", content}
	delayv.BroadcastCh <- datatosend

	starttime := time.Now()
	for _,v:=range delayv.Peers {
		delayv.WriteDelaydata[v] = MAXWAITTIME
		delayv.HashDelaydata[v] = MAXWAITTIME
	} // note do not need to set delayv.WriteDelaydata[v] = 0, because delayv.peers doesn't contain tester.

	thetimer := time.NewTimer(time.Millisecond*MAXWAITTIME)
	t1 := make(map[int]int)
	for _, v := range delayv.Peers {
		t1[v] = 0
	}
theloop:
	for {
		select {
		case <-thetimer.C:
			break theloop
		case theresponse :=<- delayv.RecvWriteResponWoFromOldCh:
			// decode response
			var wrr WriteResponseWoValidateMsg
			wrr.Deserialize(theresponse.Msg)
			// check correctness
			// update delay vector
			if delayv.Round==wrr.Round {
				t1[wrr.Testee] = int(time.Since(starttime).Milliseconds())
				delayv.WriteDelaydata[wrr.Testee] = t1[wrr.Testee]/2
				if AllUpdated(delayv.WriteDelaydata, delayv.HashDelaydata, MAXWAITTIME) {
					break theloop
				}
			} else {
				fmt.Println("the received write-response round number not matchs, current round:", delayv.Round, "response round:", wrr.Round)
			}
		case theresponse :=<- delayv.RecvWriteResponWCh:
			// decode response
			var wrr WriteResponseWithValidateMsg
			wrr.Deserialize(theresponse.Msg)
			// check correctness
			if delayv.Round==wrr.Round {
				delayv.HashDelaydata[wrr.Testee] = int(time.Since(starttime).Milliseconds()) - t1[wrr.Testee]
				if AllUpdated(delayv.WriteDelaydata, delayv.HashDelaydata, MAXWAITTIME) {
					break theloop
				}
			} else {
				fmt.Println("the received write-response round number not matchs, current round:", delayv.Round, "response round:", wrr.Round)
			}
		}
	}
}

func (delayv *DelayVector) UpdateProposeAtNew() {
	// this func blocks when executing, this func tends to overestimate propose
	// delay, but it's ok for consensus delay estimation

	// send propose
	rann := uint64(time.Now().Unix())
	ppmsg := NewProposeMsg(delayv.Tester, delayv.Round, delayv.IpAddr, delayv.Txbatch, rann)
	starttime := time.Now()

	var buff bytes.Buffer
	gob.Register(elliptic.P256())
	enc := gob.NewEncoder(&buff)
	err := enc.Encode(ppmsg)
	if err != nil {
		log.Panic(err)
	}
	content := buff.Bytes()
	datatosend := Datatosend{delayv.Peers, "proposetestfromnew", content}

	delayv.BroadcastCh <- datatosend // question, hope this won't block or take too much time

	// wait for reponse
	for _,v:=range delayv.Peers {
		delayv.ProposeDelaydata[v] = MAXWAITTIME
		delayv.ValidationDelaydata[v] = MAXWAITTIME
	}
	thetimer := time.NewTimer(time.Millisecond*MAXWAITTIME)
	t1 := make(map[int]int)
	for _, v := range delayv.Peers {
		t1[v] = 0
	}

theloop:
	for {
		select {
		case <-thetimer.C:
			break theloop
		case theresponse :=<- delayv.RecvProposeResponWoFromOldCh:
			// decode response
			var ppr ProposeResponseWoValidateMsg
			ppr.Deserialize(theresponse.Msg)
			// todo, check correctness
			if ppr.Round==delayv.Round {
				// update delay vector
				t1[ppr.Testee] = int(time.Since(starttime).Milliseconds())
				// tend to overestimate propose-delay
				delayv.ProposeDelaydata[ppr.Testee] = t1[ppr.Testee] / 2
			}
			if AllUpdated(delayv.ProposeDelaydata, delayv.ValidationDelaydata, MAXWAITTIME) {
				break theloop
			}
		case theresponse :=<- delayv.RecvProposeResponWFromOldCh:
			var ppr ProposeResponseWithValidateMsg
			ppr.Deserialize(theresponse.Msg)
			if ppr.Round==delayv.Round {
				// update delay vector
				//fmt.Println("delay vector instance receives propose-response-with-validation, updating validaton delay data")
				delayv.ValidationDelaydata[ppr.Testee] = int(time.Since(starttime).Milliseconds()) - t1[ppr.Testee]
			}
			if AllUpdated(delayv.ProposeDelaydata, delayv.ValidationDelaydata, MAXWAITTIME) {
				break theloop
			}
		}
	}
}

func (delayv *DelayVector) PrintResult() {
	//fmt.Println("---------- round", delayv.Round)
	for _, v:= range delayv.Peers {
		fmt.Println("propose-delay", delayv.Tester, "-->", v, "is", delayv.ProposeDelaydata[v])
	}
	for _, v:= range delayv.Peers {
		fmt.Println("validate-delay", delayv.Tester, "-->", v, "is", delayv.ValidationDelaydata[v])
	}
	for _, v:= range delayv.Peers {
		fmt.Println("write-delay", delayv.Tester, "-->", v, "is", delayv.WriteDelaydata[v])
	}
	for _, v:= range delayv.Peers {
		fmt.Println("hash-delay", delayv.Tester, "-->", v, "is", delayv.HashDelaydata[v])
	}
	fmt.Println("----------")
}

func AllUpdated(m1 map[int]int, m2 map[int]int, maximum int) bool {
	for _,v := range m1 {
		if v==maximum {
			return false
		}
	}
	for _,v := range m2 {
		if v==maximum {
			return false
		}
	}
	return true
}