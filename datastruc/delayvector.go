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
	for _, v := range dv.Peers {
		dv.ProposeDelaydata[v] = MAXWAITTIME // initialize to be the maximum value
		dv.WriteDelaydata[v] = MAXWAITTIME
		dv.ValidationDelaydata[v] = MAXWAITTIME
	}
	dv.Txbatch = txbatch
	dv.SendCh = cdedata.SendCh
	dv.BroadcastCh = cdedata.BroadcastCh
	dv.RecvProposeResponWoCh = cdedata.RecvProposeResponWoCh
	dv.RecvProposeResponWCh = cdedata.RecvProposeResponWCh
	dv.RecvWriteResponCh = cdedata.RecvWriteResponCh
	dv.RecvProposeResponWoFromOldCh = cdedata.RecvProposeResponWoFromOldCh
	dv.RecvProposeResponWFromOldCh = cdedata.RecvProposeResponWFromOldCh
	dv.RecvWriteResponFromOldCh = cdedata.RecvWriteResponFromOldCh

	dv.RecvProposeResponWoFromNewCh = cdedata.RecvProposeResponWoFromNewCh
	dv.RecvProposeResponWFromNewCh = cdedata.RecvProposeResponWFromNewCh
	dv.RecvWriteResponFromNewCh = cdedata.RecvWriteResponFromNewCh
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
	WriteDelaydata map[int]int
	ValidationDelaydata map[int]int
	Txbatch []Transaction
	SendCh chan DatatosendWithIp
	BroadcastCh chan Datatosend
	RecvProposeResponWoCh chan DataReceived
	RecvProposeResponWCh chan DataReceived
	RecvWriteResponCh chan DataReceived

	RecvProposeResponWoFromOldCh chan DataReceived
	RecvProposeResponWFromOldCh chan DataReceived
	RecvWriteResponFromOldCh chan DataReceived

	RecvProposeResponWoFromNewCh chan DataReceived
	RecvProposeResponWFromNewCh chan DataReceived
	RecvWriteResponFromNewCh chan DataReceived
}

func (delayv *DelayVector) Update(testop string) {

	fmt.Println("instance", delayv.Tester, "starts updating", testop, "delay vector at round", delayv.Round)
	if testop=="both" {
		delayv.UpdateWrite()
		delayv.UpdatePropose()
		//if delayv.Tester==0 {
		//	fmt.Println("propose-delay and validate-delay measurement result----------------------------------------")
		//	delayv.PrintResult()
		//}
	} else if testop=="write" {
		delayv.UpdateWrite()

	} else if testop=="propose" {
		delayv.UpdatePropose()
	} else {
		log.Panic("wrong option")
	}
}

func (delayv *DelayVector) UpdateAtNew(testop string) {
	if testop=="both" {
		delayv.UpdateWriteAtNew()
		delayv.UpdateProposeAtNew()
	} else if testop=="write" {
		delayv.UpdateWriteAtNew()
	} else if testop=="propose" {
		delayv.UpdateProposeAtNew()
	} else {
		log.Panic("wrong option")
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
				delayv.ProposeDelaydata[ppr.Testee] = int(time.Since(starttime).Milliseconds()) / 2
				//fmt.Println("instance", delayv.Tester, "measures a new propose-without-validation delay", delayv.Tester, " --> ", ppr.Testee, ":", delayv.ProposeDelaydata[ppr.Testee])
				//gotresponse[ppr.Testee] = true
			} else {
				fmt.Println("the received propose-response-wo round number not match, current round:", delayv.Round, "response round:", ppr.Round)
			}
		case theresponse :=<- delayv.RecvProposeResponWCh:
			var ppr ProposeResponseWithValidateMsg
			ppr.Deserialize(theresponse.Msg)
			if ppr.Round==delayv.Round {
				// update delay vector
				delayv.ValidationDelaydata[ppr.Testee] = int(time.Since(starttime).Milliseconds()) - t1[ppr.Testee]
				//fmt.Println("instance", delayv.Tester, "measures a new propose-response-with-validation delay", delayv.Tester, " --> ", ppr.Testee, ":", delayv.ValidationDelaydata[ppr.Testee])
				//gotresponse[ppr.Testee] = true
			}
		}
	}
}

func (delayv *DelayVector) UpdateWrite() {
	// this func blocks when executing

	// send propose and write
	rann := uint64(time.Now().Unix())
	wrmsg := NewWriteMsg(delayv.Tester, delayv.Round, delayv.IpAddr, rann)
	starttime := time.Now()

	var buff bytes.Buffer
	gob.Register(elliptic.P256())
	enc := gob.NewEncoder(&buff)
	err := enc.Encode(wrmsg)
	if err != nil {
		log.Panic(err)
	}
	content := buff.Bytes()

	datatosend := Datatosend{delayv.Peerexceptme, "writetest", content}
	delayv.BroadcastCh <- datatosend // question, hope this won't block or take too much time

	delayv.WriteDelaydata[delayv.Tester] = 0
	thetimer := time.NewTimer(time.Millisecond*MAXWAITTIME)
theloop:
	for {
		select {
		case <-thetimer.C:
			//fmt.Println("update write timer expires, breaks")
			break theloop
		case theresponse :=<- delayv.RecvWriteResponCh:
			// decode response
			var wrr WriteResponseMsg
			wrr.Deserialize(theresponse.Msg)
			// check correctness
			if delayv.Round==wrr.Round {
				// update delay vector
				delayv.WriteDelaydata[wrr.Testee] = int(time.Since(starttime).Milliseconds()/2)
			} else {
				fmt.Println("the received write-response round number not matchs, current round:", delayv.Round, "response round:", wrr.Round)
			}
		}
	}
}

func (delayv *DelayVector) UpdateWriteAtNew() {
	rann := uint64(time.Now().Unix())
	wrmsg := NewWriteMsg(delayv.Tester, delayv.Round, delayv.IpAddr, rann)
	starttime := time.Now()
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

	thetimer := time.NewTimer(time.Millisecond*MAXWAITTIME)
theloop:
	for {
		select {
		case <-thetimer.C:
			//fmt.Println("update write at new timer expires, breaks")
			break theloop
		case theresponse :=<- delayv.RecvWriteResponFromOldCh:
			// decode response
			var wrr WriteResponseMsg
			wrr.Deserialize(theresponse.Msg)
			// check correctness
			// update delay vector
			delayv.WriteDelaydata[wrr.Testee] = int(time.Since(starttime).Milliseconds()/2)
			//fmt.Println("new instance received a write-response, delay", delayv.Tester, " --> ", wrr.Testee, ":", delayv.WriteDelaydata[wrr.Testee])
			//gotresponse[wrr.Testee] = true
			//// decide to break or not
			//shouldbreak := true
			//for _,v := range gotresponse {
			//	if !v {
			//		shouldbreak = false
			//	}
			//}
			//if shouldbreak {
			//	break theloop
			//}
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
	gotresponse := make(map[int]bool)
	for _, v := range delayv.Peers {
		gotresponse[v] = false
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
				delayv.ProposeDelaydata[ppr.Testee] = int(time.Since(starttime).Milliseconds()) / 2
				gotresponse[ppr.Testee] = true
			}
		case theresponse :=<- delayv.RecvProposeResponWFromOldCh:
			var ppr ProposeResponseWithValidateMsg
			ppr.Deserialize(theresponse.Msg)
			if ppr.Round==delayv.Round {
				// update delay vector
				//fmt.Println("delay vector instance receives propose-response-with-validation, updating validaton delay data")
				delayv.ValidationDelaydata[ppr.Testee] = int(time.Since(starttime).Milliseconds()) - t1[ppr.Testee]
				gotresponse[ppr.Testee] = true
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
	fmt.Println("----------")
}