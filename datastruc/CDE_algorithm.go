package datastruc

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	b64 "encoding/base32"
	"encoding/gob"
	"fmt"
	"log"
	"sort"
	"sync"
	"time"
)

const MAXWAITTIME = 2000 // maximum waiting time for reponse message(ms)

type CDEdata struct {
	mu sync.Mutex

	Id int
	IpAddr string
	Peers []int

	Round int // the test time
	ProposeDelayMatrix map[int]map[int]int
	ValidationDelayMatrix map[int]map[int]int
	WriteDelayMatrix map[int]map[int]int
	HashDelayMatrix map[int]map[int]int


	Sanitizationflag map[int]int
	validatetxbatachtime []int
	//hashgeneratetime []int

	SendCh chan DatatosendWithIp
	BroadcastCh chan Datatosend
	RecvTestCh chan DataReceived
	RecvResponseCh chan DataReceived

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

	RecvInformTestCh chan RequestTestMsg
	RecvSingleMeasurement chan SingleMeasurementAToB

	Recvmu sync.Mutex // what for?

	Pubkeystr string
	Prvkey *ecdsa.PrivateKey
	Clientacctopuk map[string]string
	Txbatch []Transaction
}

type CDEPureDelayData struct {

	ProposeDelayMatrix map[int]map[int]int
	WriteDelayMatrix map[int]map[int]int
	ValidationDelayMatrix map[int]map[int]int
	HashDelayMatrix map[int]map[int]int

	Sanitizationflag map[int]int
}

func CreateCDEdata(id int, ip string, peers []int, sendch chan DatatosendWithIp, broadCh chan Datatosend, recvtestch chan DataReceived,
	recvresponsech chan DataReceived, RecvInformTestCh chan RequestTestMsg, recvsinglemeasurementCh chan SingleMeasurementAToB,
	pubkeystr string, prvkey *ecdsa.PrivateKey, clientpubkeystr map[int]string) *CDEdata {
	cde := &CDEdata{}

	cde.Id = id
	cde.IpAddr = ip
	cde.Peers = make([]int, 0)
	cde.ProposeDelayMatrix = make(map[int]map[int]int)
	cde.WriteDelayMatrix = make(map[int]map[int]int)
	cde.ValidationDelayMatrix = make(map[int]map[int]int)
	cde.HashDelayMatrix = make(map[int]map[int]int)
	cde.Sanitizationflag = make(map[int]int)
	le := len(peers)
	for _,v := range peers {
		cde.Peers = append(cde.Peers, v)
		cde.ProposeDelayMatrix[v] = make(map[int]int)
		cde.WriteDelayMatrix[v] = make(map[int]int)
		cde.ValidationDelayMatrix[v] = make(map[int]int)
		cde.HashDelayMatrix[v] = make(map[int]int)
		for i:=0; i<le; i++ {
			cde.ProposeDelayMatrix[v][i] = MAXWAITTIME
			cde.WriteDelayMatrix[v][i] = MAXWAITTIME
			cde.ValidationDelayMatrix[v][i] = MAXWAITTIME
			cde.HashDelayMatrix[v][i] = MAXWAITTIME
		}
	}

	cde.Round = 1
	cde.SendCh = sendch
	cde.BroadcastCh = broadCh
	cde.RecvTestCh = recvtestch
	cde.RecvResponseCh = recvresponsech

	cde.RecvProposeResponWoCh = make(chan DataReceived)
	cde.RecvProposeResponWCh = make(chan DataReceived)
	cde.RecvWriteResponWoCh = make(chan DataReceived)
	cde.RecvWriteResponWCh = make(chan DataReceived)

	cde.RecvProposeResponWoFromOldCh = make(chan DataReceived)
	cde.RecvProposeResponWFromOldCh = make(chan DataReceived)
	cde.RecvWriteResponWoFromOldCh = make(chan DataReceived)
	cde.RecvWriteResponWFromOldCh = make(chan DataReceived)

	cde.RecvProposeResponWoFromNewCh = make(chan DataReceived)
	cde.RecvProposeResponWFromNewCh = make(chan DataReceived)
	cde.RecvWriteResponWoFromNewCh = make(chan DataReceived)
	cde.RecvWriteResponWFromNewCh = make(chan DataReceived)

	cde.RecvSingleMeasurement = recvsinglemeasurementCh
	cde.RecvInformTestCh = RecvInformTestCh

	cde.Pubkeystr = pubkeystr
	cde.Prvkey = prvkey
	cde.Clientacctopuk = make(map[string]string)
	for _,v := range clientpubkeystr {
		hv := sha256.Sum256([]byte(v))
		acc := b64.StdEncoding.EncodeToString(hv[:])
		cde.Clientacctopuk[acc] = v
	}

	return cde
}


func (cdedata *CDEdata) responseProposeWoValidate(proposetestmsg ProposeTestMsg, replytonew bool) {
	pprmsg := NewProposeResponseWoValidateMsg(cdedata.Id, proposetestmsg.Round, proposetestmsg.Challange, proposetestmsg.TxBatch)
	var buff bytes.Buffer
	gob.Register(elliptic.P256())
	enc := gob.NewEncoder(&buff)
	err := enc.Encode(pprmsg)
	if err != nil {
		log.Panic(err)
	}
	content := buff.Bytes()


	if replytonew {
		destip := make([]string, 0)
		tmp := proposetestmsg.IpAddr
		destip = append(destip, tmp)
		datatosend := DatatosendWithIp{destip, "proporesponwofromold", content}
		cdedata.SendCh <- datatosend
	} else {
		dest := make([]int, 0)
		dest = append(dest, proposetestmsg.Tester)
		datatosend := Datatosend{dest, "proporesponwo", content}
		cdedata.BroadcastCh <- datatosend
	}

	//fmt.Println("instance", cdedata.Id, "responses without validation to propose-test-", proposetestmsg.Round)
}

func (cdedata *CDEdata) responseProposeWithValidate(proposetestmsg ProposeTestMsg, replytonew bool) {
	// validate txlist, it will took some time
	reslist := make([]bool, 0)
	//for _, tx := range proposetestmsg.TxBatch {
	//	reslist = append(reslist, tx.Verify(cdedata.Clientacctopuk[tx.Source]))
	//}

	if replytonew {
		if len(cdedata.validatetxbatachtime)==0 {
			time.Sleep(time.Duration(200)*time.Millisecond)
		} else {
			t := 0
			for _,v := range cdedata.validatetxbatachtime {
				t += v
			}
			t = t/len(cdedata.validatetxbatachtime)
			fmt.Println("sleep to replace validation, time:", t, "ms")
			time.Sleep(time.Duration(t)*time.Millisecond)
		}
	} else {
		start := time.Now()
		cdedata.TxListValidateMultiThread(proposetestmsg.TxBatch)
		elapsed := time.Since(start).Milliseconds()
		fmt.Println("instance", cdedata.Id, "validation_for_test costs", elapsed, "ms, tx nubmer:", len(proposetestmsg.TxBatch))
		cdedata.validatetxbatachtime = append(cdedata.validatetxbatachtime, int(elapsed))
		// todo, only add the value when it is in consensus. If it is a new node, do not add that.
		// sleep for time t, t equals the time to validate tx batach
	}

	pprmsg := NewProposeResponseWithValidateMsg(cdedata.Id, proposetestmsg.Round, proposetestmsg.Challange, reslist, proposetestmsg.TxBatch)
	var buff bytes.Buffer
	gob.Register(elliptic.P256())
	enc := gob.NewEncoder(&buff)
	err := enc.Encode(pprmsg)
	if err != nil {
		log.Panic(err)
	}
	content := buff.Bytes()

	if replytonew {
		destip := make([]string, 0)
		tmp := proposetestmsg.IpAddr
		//le := len(tmp)
		//theipprefix := tmp[0:(le-1)]
		//theremoteip := theipprefix + strconv.Itoa(cdedata.Id)
		//destip = append(destip, theremoteip)
		destip = append(destip, tmp)
		datatosend := DatatosendWithIp{destip, "proporesponwfromold", content}
		cdedata.SendCh <- datatosend
	} else {
		dest := make([]int, 0)
		dest = append(dest, proposetestmsg.Tester)
		datatosend := Datatosend{dest, "proporesponw", content}
		cdedata.BroadcastCh <- datatosend
	}
}

func (cdedata *CDEdata) responseWriteWoHash(writetestmsg WriteTestMsg, replytonew bool) {
	wrrmsg := NewWriteResponseWoHashMsg(cdedata.Id, writetestmsg.Round, writetestmsg.Challange)
	var buff bytes.Buffer
	gob.Register(elliptic.P256())
	enc := gob.NewEncoder(&buff)
	err := enc.Encode(wrrmsg)
	if err != nil {
		log.Panic(err)
	}
	content := buff.Bytes()

	if replytonew {
		destip := make([]string, 0)
		tmp := writetestmsg.IpAddr
		destip = append(destip, tmp)
		datatosend := DatatosendWithIp{destip, "writeresponwofromold", content}
		cdedata.SendCh <- datatosend
	} else {
		dest := make([]int, 0)
		dest = append(dest, writetestmsg.Tester)
		datatosend := Datatosend{dest, "writeresponwo", content}
		cdedata.BroadcastCh <- datatosend
	}
}

//func (cdedata *CDEdata) responseWriteWithHash(writetestmsg WriteTestMsg, replytonew bool) {
//	var hv [32]byte
//
//	if replytonew {
//		if len(cdedata.hashgeneratetime)==0 {
//			time.Sleep(time.Duration(50)*time.Millisecond)
//		} else {
//			t := 0
//			for _,v := range cdedata.hashgeneratetime {
//				t += v
//			}
//			t = t/len(cdedata.hashgeneratetime)
//			fmt.Println("sleep to replace system_hash_generation, time:", t, "ms")
//			time.Sleep(time.Duration(t)*time.Millisecond)
//		}
//	} else {
//		start := time.Now()
//		var content []byte
//		for i:=0; i<20000; i++ {
//			EncodeInt(&content, i)
//		}
//		hv = sha256.Sum256(content)
//		elaps := int(time.Since(start).Milliseconds())
//		cdedata.hashgeneratetime = append(cdedata.hashgeneratetime, elaps)
//		fmt.Println("instance", cdedata.Id, "generate_account_balance_hash_costs", elaps, "ms")
//	}
//
//	wrrmsg := NewWriteResponseWithHashMsg(cdedata.Id, writetestmsg.Round, writetestmsg.Challange, hv)
//	var buff bytes.Buffer
//	gob.Register(elliptic.P256())
//	enc := gob.NewEncoder(&buff)
//	err := enc.Encode(wrrmsg)
//	if err != nil {
//		log.Panic(err)
//	}
//	content := buff.Bytes()
//
//	if replytonew {
//		destip := make([]string, 0)
//		tmp := writetestmsg.IpAddr
//		destip = append(destip, tmp)
//		datatosend := DatatosendWithIp{destip, "writeresponwfromold", content}
//		cdedata.SendCh <- datatosend
//	} else {
//		dest := make([]int, 0)
//		dest = append(dest, writetestmsg.Tester)
//		datatosend := Datatosend{dest, "writeresponw", content}
//		cdedata.BroadcastCh <- datatosend
//	}
//}

func (cdedata *CDEdata) CDETestMonitor(closeCh chan bool) {
	// respond when receiving a test.
theloop:
	for {
		select {
		case thetest :=<-cdedata.RecvTestCh:
			switch thetest.MsgType {
			case "proposetest":
				var proposetest ProposeTestMsg
				proposetest.Deserialize(thetest.Msg)
				go cdedata.responseProposeWoValidate(proposetest, false)
				go cdedata.responseProposeWithValidate(proposetest, false)
			case "writetest":
				var writetest WriteTestMsg
				writetest.Deserialize(thetest.Msg)
				go cdedata.responseWriteWoHash(writetest, false)
				//go cdedata.responseWriteWithHash(writetest, false)
			case "proposetestfromnew":
				var proposetest ProposeTestMsg
				proposetest.Deserialize(thetest.Msg)
				go cdedata.responseProposeWoValidate(proposetest, true)
				go cdedata.responseProposeWithValidate(proposetest, true)
			case "writetestfromnew":
				var writetest WriteTestMsg
				writetest.Deserialize(thetest.Msg)
				fmt.Println("instance", cdedata.Id, "receives a write-test from new")
				go cdedata.responseWriteWoHash(writetest, true)
				//go cdedata.responseWriteWithHash(writetest, true)
			case "proposetestfromold":
				var proposetest ProposeTestMsg
				proposetest.Deserialize(thetest.Msg)
				go cdedata.responseProposeWoValidate(proposetest, false)
				go cdedata.responseProposeWithValidate(proposetest, false)
			case "writetestfromold":
				var writetest WriteTestMsg
				writetest.Deserialize(thetest.Msg)
				//fmt.Println("instance", cdedata.Id, "receives a write-test from old instance")
				go cdedata.responseWriteWoHash(writetest, false)
				//go cdedata.responseWriteWithHash(writetest, false)
			}
		case <-closeCh:
			//fmt.Println("CDEResponseMonitor function exits")
			break theloop
		}
	}
}

func (cdedata *CDEdata) CDEResponseMonitor(closeCh chan bool) {
	// process the response when receiving it
theloop:
	for {
		select {
		case theresponse :=<- cdedata.RecvResponseCh:
			switch theresponse.MsgType {
			case "proporesponwo":
				cdedata.RecvProposeResponWoCh <- theresponse
			case "proporesponw":
				cdedata.RecvProposeResponWCh <- theresponse
			case "writeresponwo":
				cdedata.RecvWriteResponWoCh <- theresponse
			case "writeresponw":
				cdedata.RecvWriteResponWCh <- theresponse
			case "proporesponwofromnew":
				cdedata.RecvProposeResponWoFromNewCh <- theresponse
			case "proporesponwfromnew":
				cdedata.RecvProposeResponWFromNewCh <- theresponse
			case "proporesponwofromold":
				cdedata.RecvProposeResponWoFromOldCh <- theresponse
			case "proporesponwfromold":
				cdedata.RecvProposeResponWFromOldCh <- theresponse
			case "writeresponwofromold":
				cdedata.RecvWriteResponWoFromOldCh <- theresponse
			case "writeresponwfromold":
				cdedata.RecvWriteResponWFromOldCh <- theresponse
			case "writeresponwofromnew":
				cdedata.RecvWriteResponWoFromNewCh <- theresponse
			case "writeresponwfromnew":
				cdedata.RecvWriteResponWoFromNewCh <- theresponse
			}
		case <-closeCh:
			//fmt.Println("CDEResponseMonitor function exits")
			break theloop
		}
	}
}

func (cdedata *CDEdata) CDEInformTestMonitor() {
	for {
		select {
		case informtestmsg :=<- cdedata.RecvInformTestCh:
			go cdedata.FullTestNewNode(informtestmsg)
		}
	}
}

func (cdedata *CDEdata) FullTestNewNode(reqtest RequestTestMsg) {
	fmt.Println("instance ", cdedata.Id, " starts full testing new instance", reqtest.Testee)
	testee := reqtest.Testee
	testeeip := reqtest.IpAddr
	delays := make([]int, 0)
	for i:=0; i<4; i++ {
		delays = append(delays, MAXWAITTIME)
	}
	delays[1] = 0
	dests := make([]string, 0)
	dests = append(dests, testeeip)
	closed := make(chan bool)
	cdedata.Recvmu.Lock()
	go cdedata.CDEResponseMonitor(closed)


	// ------------------------------------------------------- test write self->new
	// pack a write-test message
	rann := uint64(time.Now().Unix())
	wrmsg := NewWriteMsg(cdedata.Id, cdedata.Round, cdedata.IpAddr, rann)


	var buff1 bytes.Buffer
	gob.Register(elliptic.P256())
	enc := gob.NewEncoder(&buff1)
	err := enc.Encode(wrmsg)
	if err != nil {
		log.Panic(err)
	}
	content := buff1.Bytes()
	datatosend := DatatosendWithIp{dests	, "writetestfromold", content}
	cdedata.SendCh <- datatosend

	// block, wait for response
	starttime1 := time.Now()
	t1 := 0
	thetimer := time.NewTimer(time.Millisecond * MAXWAITTIME)
	theloop1:
	for {
		select {
		case <-thetimer.C:
			break theloop1
		case theresponse := <- cdedata.RecvWriteResponWoCh:
			var wrr WriteResponseWoValidateMsg
			wrr.Deserialize(theresponse.Msg)
			if wrr.Testee==testee && wrr.Challange==rann {
				t1 = int(time.Since(starttime1).Milliseconds())
				delays[0] = t1/2
				//fmt.Println("instance", cdedata.Id, "measure write-delay to new instance: ", cdedata.Id, " --> ", testee, ":", delays[0])
				if delays[0]<MAXWAITTIME && delays[1]<MAXWAITTIME {
					break theloop1
				}
			}
		case theresponse := <- cdedata.RecvWriteResponWCh:
			var wrr WriteResponseWithValidateMsg
			wrr.Deserialize(theresponse.Msg)
			if wrr.Testee==testee && wrr.Challange==rann {
				delays[1] = int(time.Since(starttime1).Milliseconds()) - t1
				if delays[0]<MAXWAITTIME && delays[1]<MAXWAITTIME {
					break theloop1
				}
			}
		}
	}

	// ------------------------------------------------------- test propose self->new and validate self->new
	// pack a propose-test message
	rann = uint64(time.Now().Unix())
	ppmsg := NewProposeMsg(cdedata.Id, cdedata.Round, cdedata.IpAddr, cdedata.Txbatch, rann)
	//  todo, xxxxxxxxxxxxxx

	var buff2 bytes.Buffer
	gob.Register(elliptic.P256())
	enc2 := gob.NewEncoder(&buff2)
	err2 := enc2.Encode(ppmsg)
	if err2 != nil {
		log.Panic(err)
	}
	content2 := buff2.Bytes()
	datatosend = DatatosendWithIp{dests, "proposetestfromold", content2}
	cdedata.SendCh <- datatosend

	// block, wait for response
	t2 := 0
	thetimer = time.NewTimer(time.Millisecond * MAXWAITTIME)
	starttime2 := time.Now()

	theloop2:
	for {
		select {
		case <-thetimer.C:
			break theloop2
		case theresponse :=<- cdedata.RecvProposeResponWoCh:
			var ppr ProposeResponseWoValidateMsg
			ppr.Deserialize(theresponse.Msg)
			if ppr.Round==cdedata.Round && ppr.Challange==rann {
				t2 = int(time.Since(starttime2).Milliseconds())
				delays[2] = t2 / 2
				if delays[2]<MAXWAITTIME && delays[3]<MAXWAITTIME {
					break theloop2
				}
			} else {
				//fmt.Println("isntance", cdedata.Id, "wrong measures propose-delay, ", cdedata.Id, " --> ", testee, ":", delays[1])
			}
		case theresponse :=<- cdedata.RecvProposeResponWCh:
			var ppr ProposeResponseWithValidateMsg
			ppr.Deserialize(theresponse.Msg)
			if ppr.Round==cdedata.Round && ppr.Challange==rann {
				delays[3] = int(time.Since(starttime2).Milliseconds()) - t2
				//fmt.Println("instance", cdedata.Id, "measure validate-delay to new instance: ", cdedata.Id, "--> ", testee, ":", delays[2])
				if delays[2]<MAXWAITTIME && delays[3]<MAXWAITTIME {
					break theloop2
				}
			}
		}
	}

	closed <- true
	cdedata.Recvmu.Unlock()



	// ------------------------------------------------------- send test res to new
	fmt.Println("instance", cdedata.Id, "completes test for new node, propose_validate_write_hashgenerate delay respectively is",
		delays[2], delays[3], delays[0], delays[1])
	smmsg := NewSingleMeasurement(cdedata.Id, testee, delays, cdedata.Pubkeystr, cdedata.Prvkey)
	fmt.Println("single measurement result:", smmsg)
	var buff3 bytes.Buffer
	gob.Register(elliptic.P256())
	enc3 := gob.NewEncoder(&buff3)
	err3 := enc3.Encode(smmsg)
	if err3 != nil {
		log.Panic(err)
	}
	content3 := buff3.Bytes()

	datatosend = DatatosendWithIp{dests, "singlemeasurement", content3}
	cdedata.SendCh <- datatosend
}

func (cdedata *CDEdata) UpdateUsingNewMeasurementRes(mrrlist []MeasurementResultMsg) {
	cdedata.mu.Lock()
	defer cdedata.mu.Unlock()

	for _, mrr := range mrrlist {
		if !PeersMatch(cdedata.Peers, mrr.Peers) {
			log.Panic("the current config does not match measurement result's config")
		}
		tester := mrr.Id
		if cdedata.Sanitizationflag[tester]==0 {
			cdedata.ProposeDelayMatrix[tester] = mrr.ProposeDealy
			cdedata.ValidationDelayMatrix[tester] = mrr.ValidateDelay
			cdedata.WriteDelayMatrix[tester] = mrr.WriteDelay
			cdedata.HashDelayMatrix[tester] = mrr.HashDelay
		} else {
		 	k:= cdedata.Sanitizationflag[tester]
			cdedata.ProposeDelayMatrix[tester] = AvgDelayMatrix(cdedata.ProposeDelayMatrix[tester], mrr.ProposeDealy, k)
			cdedata.ValidationDelayMatrix[tester] = AvgDelayMatrix(cdedata.ValidationDelayMatrix[tester], mrr.ValidateDelay, k)
			cdedata.WriteDelayMatrix[tester] = AvgDelayMatrix(cdedata.WriteDelayMatrix[tester], mrr.WriteDelay, k)
			cdedata.HashDelayMatrix[tester] = AvgDelayMatrix(cdedata.HashDelayMatrix[tester], mrr.HashDelay, k)
		}
		cdedata.Sanitizationflag[tester] += 1
	}
}

func AvgDelayMatrix(dm map[int]int, data map[int]int, t int) map[int]int {
	res := make(map[int]int)

	for k,v := range dm {
		res[k] = int((v*t + data[k])/(t+1))
	}
	return res
}

func (cdedata *CDEdata) ProposeDelayConvertToMatrix() [][]int {
	cdedata.mu.Lock()
	res := make([][]int, 0)
	for _, v := range cdedata.Peers {
		tmp := make([]int, 0)
		for _, u := range cdedata.Peers {
			tmp = append(tmp, cdedata.ProposeDelayMatrix[v][u])
		}
		res = append(res, tmp)
	}

	cdedata.mu.Unlock()
	return res
}

func (cdedata *CDEdata) ValidationDelayConverToMatrix() [][]int {
	cdedata.mu.Lock()
	res := make([][]int, 0)

	for _, v := range cdedata.Peers {
		tmp := make([]int, 0)
		for _, u := range cdedata.Peers {
			tmp = append(tmp, cdedata.ValidationDelayMatrix[v][u])
		}
		res = append(res, tmp)
	}

	cdedata.mu.Unlock()
	return res
}

func (cdedata *CDEdata) WriteDelayConvertToMatrix() [][]int {
	cdedata.mu.Lock()

	res := make([][]int, 0)
	for _, v := range cdedata.Peers {
		tmp := make([]int, 0)
		for _, u := range cdedata.Peers {
			tmp = append(tmp, cdedata.WriteDelayMatrix[v][u])
		}
		res = append(res, tmp)
	}

	cdedata.mu.Unlock()
	return res
}

func (cdedata *CDEdata) HashDelayConvertToMatrix() [][]int {
	cdedata.mu.Lock()

	res := make([][]int, 0)
	for _, v := range cdedata.Peers {
		tmp := make([]int, 0)
		for _, u := range cdedata.Peers {
			tmp = append(tmp, cdedata.HashDelayMatrix[v][u])
		}
		res = append(res, tmp)
	}

	cdedata.mu.Unlock()
	return res
}

func (cdedata *CDEdata) PrintResult() {
	cdedata.mu.Lock()
	defer cdedata.mu.Unlock()

	fmt.Println("---------- instance", cdedata.Id, "propose-delay round", cdedata.Round)
	for _, i := range cdedata.Peers {
		for _, j := range cdedata.Peers {
			fmt.Printf("%d --> %d: %d     ", i, j, cdedata.ProposeDelayMatrix[i][j])
		}
		fmt.Printf("\n")
	}
	fmt.Println("----------instance", cdedata.Id, "validation-delay round", cdedata.Round)
	for _, i := range cdedata.Peers {
		for _, j := range cdedata.Peers {
			fmt.Printf("%d --> %d: %d     ", i, j, cdedata.ValidationDelayMatrix[i][j])
		}
		fmt.Printf("\n")
	}
	fmt.Println("----------instance", cdedata.Id ,"write-delay round", cdedata.Round)
	for _, i := range cdedata.Peers {
		for _, j := range cdedata.Peers {
			fmt.Printf("%d --> %d: %d     ", i, j, cdedata.WriteDelayMatrix[i][j])
		}
		fmt.Printf("\n")
	}
	fmt.Println("----------instance", cdedata.Id ,"hash-delay round", cdedata.Round)
	for _, i := range cdedata.Peers {
		for _, j := range cdedata.Peers {
			fmt.Printf("%d --> %d: %d     ", i, j, cdedata.HashDelayMatrix[i][j])
		}
		fmt.Printf("\n")
	}
	fmt.Println("----------")
}

func (cdedata *CDEdata) GenerateStateHash() [32]byte {

	proposetwodlistrepresent := make([]int, 0)
	for _,v := range cdedata.Peers {
		for _,u := range cdedata.Peers {
			proposetwodlistrepresent = append(proposetwodlistrepresent, cdedata.ProposeDelayMatrix[v][u])
		}
	}
	validatetwodlistrepresent := make([]int, 0)
	for _, v := range cdedata.Peers {
		for _,u := range cdedata.Peers {
			validatetwodlistrepresent = append(validatetwodlistrepresent, cdedata.ValidationDelayMatrix[v][u])
		}
	}
	writetwodlistrepresent := make([]int, 0)
	for _,v := range cdedata.Peers {
		for _,u := range cdedata.Peers {
			writetwodlistrepresent = append(writetwodlistrepresent, cdedata.WriteDelayMatrix[v][u])
		}
	}
	hashtwodlistrepresent := make([]int, 0)
	for _,v := range cdedata.Peers {
		for _,u := range cdedata.Peers {
			writetwodlistrepresent = append(hashtwodlistrepresent, cdedata.HashDelayMatrix[v][u])
		}
	}
	tmp1 := append(cdedata.Peers, proposetwodlistrepresent...)
	tmp2 := append(tmp1, validatetwodlistrepresent...)
	tmp3 := append(tmp2, writetwodlistrepresent...)
	thefinallist := append(tmp3, hashtwodlistrepresent...)

	var content []byte
	for _,v := range thefinallist {
		EncodeInt(&content, v)
	}
	hashv := sha256.Sum256(content)
	return hashv
}

func (cdedata *CDEdata) CollectDelayDataForNew(txbatch []Transaction) JoinTx {


	closech := make(chan bool)
	cdedata.Recvmu.Lock()
	go cdedata.CDEResponseMonitor(closech)


	// update write new->system, then update propose new->system
	fmt.Println("new instance starts update delay new --> system")
	delayv := cdedata.CreateDelayVector(txbatch)
	delayv.UpdateWriteAtNew()
	time.Sleep(time.Millisecond * 20)
	// update propose new->sytem
	delayv.UpdateProposeAtNew()
	delayv.PrintResult() // print delay it->system
	//closech<-true
	mrmsg := NewMeasurementResultMsg(cdedata.Id, cdedata.Round, cdedata.Peers, delayv.ProposeDelaydata,
		delayv.WriteDelaydata, delayv.ValidationDelaydata, delayv.HashDelaydata, cdedata.Pubkeystr, cdedata.Prvkey)
	time.Sleep(time.Millisecond * 20)

	closech<-true
	cdedata.Recvmu.Unlock() // cdedata.CDEResponseMonitor

	// for node in system: update node->new one by one
	go cdedata.CDETestMonitor(closech)
	inverseproposedelay := make(map[int]int)
	inversevalidatedelay := make(map[int]int)
	inversewritedelay := make(map[int]int)
	inversehashdelay := make(map[int]int)
	for _, i := range cdedata.Peers {
		// inform instance i to test itself
		for {
			singlemmsg := cdedata.InformTestInstance(i) // block, until receives the test result with signature
			if singlemmsg.Validatedelay<900 {
				// test until it is satisfied
				inverseproposedelay[i] = singlemmsg.Proposedelay
				inversevalidatedelay[i] = singlemmsg.Validatedelay
				inversewritedelay[i] = singlemmsg.Writedelay
				inversehashdelay[i] = singlemmsg.Hashdelay
				break
			} else {
				time.Sleep(time.Millisecond * 20)
			}
		}
		time.Sleep(time.Millisecond * 20)
	}
	imrmsg := NewInverseMeasurementResultMsg(cdedata.Id, cdedata.Round, cdedata.Peers, inverseproposedelay,
		inversevalidatedelay, inversewritedelay, inversehashdelay, cdedata.Pubkeystr, cdedata.Prvkey)
	// print delay system->it
	fmt.Println("inverse propose-delay is", inverseproposedelay)
	fmt.Println("inverse validate-delay is", inversevalidatedelay)
	fmt.Println("inverse write-delay is", inversewritedelay)
	fmt.Println("inverse hash-delay is", inversehashdelay)

	closech<-true // stop cdedata.CDETestMonitor(closech)

	// create join-tx for new instance
	fmt.Println("new instance creates join-tx")
	jtx := NewJoinTx(cdedata.Id, cdedata.IpAddr, mrmsg, imrmsg, cdedata.Pubkeystr, cdedata.Prvkey)
	fmt.Println("instance", cdedata.Id, "update at round", cdedata.Round, "completes")
	cdedata.Round += 1
	fmt.Println("the join-tx:", jtx)
	fmt.Println("measurement msg, propose_validate_write_hash delay:", mrmsg.ProposeDealy, mrmsg.ValidateDelay, mrmsg.WriteDelay, mrmsg.HashDelay)
	fmt.Println("inv measurement msg, propose_validate_write_hash delay:", imrmsg.ProposeDealy, imrmsg.ValidateDelay, imrmsg.WriteDelay, imrmsg.HashDelay)
	return jtx
}

func (cdedata *CDEdata) InformTestInstance(dest int) SingleMeasurementAToB {
	reqtestmsg := NewRequestTestMsg(cdedata.Id, cdedata.IpAddr)
	var buff bytes.Buffer
	gob.Register(elliptic.P256())
	enc := gob.NewEncoder(&buff)
	err := enc.Encode(reqtestmsg)
	if err != nil {
		log.Panic(err)
	}
	content := buff.Bytes()

	dests := make([]int, 0)
	dests = append(dests, dest)
	datatosend := Datatosend{dests, "informtest", content}
	cdedata.BroadcastCh <- datatosend

	// block here, until receive test result (proposedelay, validatedelay, writedelay)
	singlemmsg :=<- cdedata.RecvSingleMeasurement

	return singlemmsg
}

func (cdedata *CDEdata) CalculateConsensusDelay(l, N, Q int) []int {
	//cdedata.mu.Lock()
	//defer cdedata.mu.Unlock()

	cdeda := cdedata.CopyData()

	sanitize := true
	for _, id := range cdeda.Peers {
		if cdeda.Sanitizationflag[id] == 0 {
			sanitize =false
		}
	}
	if sanitize {
		cdeda.Sanitization()
		fmt.Println("sanitization happens at the copy of cdedata when calculating consensus delay for static system")
	}



	blockdelay := cdeda.ProposeDelayConvertToMatrix()
	validatedelay := cdeda.ValidationDelayConverToMatrix()
	votedelay := cdeda.WriteDelayConvertToMatrix()
	if l==0 {
		fmt.Println("the cdeda in calculation\n\n")
		cdeda.PrintResult()
		fmt.Println("blockdelay:", blockdelay)
		fmt.Println("\n\nthe end\n\n")
	}

	K := 5
	Time_recv_pre_prepare := make([][]int, K)
	for i:=0; i<K; i++ {
		Time_recv_pre_prepare[i] = make([]int, N)
	}
	Time_recv_prepare := make([][]int, N)
	for i:=0; i<N; i++ {
		Time_recv_prepare[i] = make([]int, N)
	}
	Time_recv_commit := make([][]int, N)
	for i:=0; i<N; i++ {
		Time_recv_commit[i] = make([]int, N)
	}
	Time_prepare := make([][]int, K)
	for i:=0; i<K; i++ {
		Time_prepare[i] = make([]int, N)
	}
	Time_commit := make([][]int, K)
	for i:=0; i<K; i++ {
		Time_commit[i] = make([]int, N)
	}


	for k:=0; k<K; k++ {
		for i:=0; i<N; i++ {
			if k==0 {
				Time_recv_pre_prepare[k][i] = blockdelay[l][i]+validatedelay[l][i]
			} else {
				Time_recv_pre_prepare[k][i] = Takemax(Time_commit[k-1][l]+blockdelay[l][i]+validatedelay[l][i], Time_commit[k-1][i])
			}
		}


		for i:=0; i<N; i++ {
			for j:=0; j<N; j++ {
				Time_recv_prepare[i][j] = Time_recv_pre_prepare[k][j]+votedelay[j][i]
			}
			sort.Ints(Time_recv_prepare[i])

		}

		for i:=0; i<N; i++ {
			Time_prepare[k][i] = Takemax(Time_recv_prepare[i][Q-1], Time_recv_pre_prepare[k][i])
		}

		for i:=0; i<N; i++ {
			for j:=0; j<N; j++ {
				Time_recv_commit[i][j] = Time_prepare[k][j]+votedelay[j][i]
			}
			sort.Ints(Time_recv_commit[i])
		}

		for i:=0; i<N; i++ {
			Time_commit[k][i] = Takemax(Time_recv_commit[i][Q-1], Time_prepare[k][i])
		}
	}

	res := make([]int, N)
	for i:=0; i<N; i++ {
		res[i] = Time_commit[K-1][i] / K
	}
	fmt.Println("calculate consensus delay, Leader:", l, "Total:", N, "Quorumsize:", Q, "result: ", res)
	return res
}

func (cdedata *CDEdata) CalculateConsensusDelayForNewJointx(l, N, Q int, jtx JoinTx) []int {
	cdedata.mu.Lock()
	defer cdedata.mu.Unlock()

	newcdedata := cdedata.CopyData() // current cdedata dimension is N-1
	fmt.Println("invoke consensus delay calculation for new join, leader is", l, "total number is", N, "qurorum size is", Q)
	newcdedata.AddNewInstanceData(jtx) // cdedata dimension becomes N after adding the new node

	fmt.Println("\n~~~~~~~~~~~~~~~~newcdedata in CalculateConsensusDelayForNewJointx~~~~~~~~~~~~~~~~~~~~~~~~~")
	newcdedata.PrintResult()
	fmt.Println("~~~~~~~~~~~~~~~~newcdedata in CalculateConsensusDelayForNewJointx~~~~~~~~~~~~~~~~~~~~~~~~~\n")
	sanitize := true
	for _, id := range newcdedata.Peers {
		if newcdedata.Sanitizationflag[id] == 0 {
			sanitize =false
		}
	}
	if sanitize {
		newcdedata.Sanitization()
		fmt.Println("sanitization happens when calculating consensus delay for adding new instance")
	}

	blockdelay := newcdedata.ProposeDelayConvertToMatrix()
	validatedelay := newcdedata.ValidationDelayConverToMatrix()
	votedelay := newcdedata.WriteDelayConvertToMatrix()

	K := 5
	Time_recv_pre_prepare := make([][]int, K)
	for i:=0; i<K; i++ {
		Time_recv_pre_prepare[i] = make([]int, N)
	}
	Time_recv_prepare := make([][]int, N)
	for i:=0; i<N; i++ {
		Time_recv_prepare[i] = make([]int, N)
	}
	Time_recv_commit := make([][]int, N)
	for i:=0; i<N; i++ {
		Time_recv_commit[i] = make([]int, N)
	}
	Time_prepare := make([][]int, K)
	for i:=0; i<K; i++ {
		Time_prepare[i] = make([]int, N)
	}
	Time_commit := make([][]int, K)
	for i:=0; i<K; i++ {
		Time_commit[i] = make([]int, N)
	}


	for k:=0; k<K; k++ {
		for i:=0; i<N; i++ {
			if k==0 {
				Time_recv_pre_prepare[k][i] = blockdelay[l][i]+validatedelay[l][i]
			} else {
				Time_recv_pre_prepare[k][i] = Takemax(Time_commit[k-1][l]+blockdelay[l][i]+validatedelay[l][i], Time_commit[k-1][i])
			}
		}


		for i:=0; i<N; i++ {
			for j:=0; j<N; j++ {
				Time_recv_prepare[i][j] = Time_recv_pre_prepare[k][j]+votedelay[j][i]
			}
			sort.Ints(Time_recv_prepare[i])

		}

		for i:=0; i<N; i++ {
			Time_prepare[k][i] = Takemax(Time_recv_prepare[i][Q-1], Time_recv_pre_prepare[k][i])
		}

		for i:=0; i<N; i++ {
			for j:=0; j<N; j++ {
				Time_recv_commit[i][j] = Time_prepare[k][j]+votedelay[j][i]
			}
			sort.Ints(Time_recv_commit[i])
		}

		for i:=0; i<N; i++ {
			Time_commit[k][i] = Takemax(Time_recv_commit[i][Q-1], Time_prepare[k][i])
		}
	}

	res := make([]int, N)
	for i:=0; i<N; i++ {
		res[i] = Time_commit[K-1][i] / K
	}
	return res
}

func (cdedata *CDEdata) CopyData() CDEdata {
	newcdedata := CDEdata{}
	newcdedata.Id = cdedata.Id
	newcdedata.IpAddr = cdedata.IpAddr
	newcdedata.Peers = cdedata.Peers

	newcdedata.ProposeDelayMatrix = make(map[int]map[int]int)
	newcdedata.ValidationDelayMatrix = make(map[int]map[int]int)
	newcdedata.WriteDelayMatrix = make(map[int]map[int]int)
	newcdedata.HashDelayMatrix = make(map[int]map[int]int)

	for _,v := range newcdedata.Peers {
		newcdedata.ProposeDelayMatrix[v] = make(map[int]int)
		newcdedata.WriteDelayMatrix[v] = make(map[int]int)
		newcdedata.ValidationDelayMatrix[v] = make(map[int]int)
		newcdedata.HashDelayMatrix[v] = make(map[int]int)


		for ke,va:=range cdedata.ProposeDelayMatrix[v] {
			newcdedata.ProposeDelayMatrix[v][ke] = va
		}
		for ke,va := range cdedata.ValidationDelayMatrix[v] {
			newcdedata.ValidationDelayMatrix[v][ke] = va
		}
		for ke,va := range cdedata.WriteDelayMatrix[v] {
			newcdedata.WriteDelayMatrix[v][ke] = va
		}
		for ke,va := range cdedata.HashDelayMatrix[v] {
			newcdedata.HashDelayMatrix[v][ke] = va
		}

	}
	newcdedata.Sanitizationflag = make(map[int]int)
	for k,v:=range cdedata.Sanitizationflag {
		newcdedata.Sanitizationflag[k] = v
	}
	return newcdedata
}

func (cdedata *CDEdata) Sanitization() {

	for _, i := range cdedata.Peers {
		for _, j:= range cdedata.Peers {
			t1 := Takemax(cdedata.ProposeDelayMatrix[i][j], cdedata.ProposeDelayMatrix[j][i])
			cdedata.ProposeDelayMatrix[i][j] = t1
			cdedata.ProposeDelayMatrix[j][i] = t1

			t2 := Takemax(cdedata.ValidationDelayMatrix[i][j], cdedata.ValidationDelayMatrix[j][i])
			cdedata.ValidationDelayMatrix[i][j] = t2
			cdedata.ValidationDelayMatrix[j][i] = t2

			t3 := Takemax(cdedata.WriteDelayMatrix[i][j], cdedata.WriteDelayMatrix[j][i])
			cdedata.WriteDelayMatrix[i][j] = t3
			cdedata.WriteDelayMatrix[j][i] = t3

			t4 := Takemax(cdedata.HashDelayMatrix[i][j], cdedata.HashDelayMatrix[j][i])
			cdedata.HashDelayMatrix[i][j] = t4
			cdedata.HashDelayMatrix[j][i] = t4
		}
	}
}

func (cdedata *CDEdata) AddNewInstanceData(jtx JoinTx) {
	newid := jtx.Id
	cdedata.Peers = append(cdedata.Peers, newid)
	for i := range cdedata.Peers {
		cdedata.Sanitizationflag[i] = 1
	}
	cdedata.ProposeDelayMatrix[newid] = make(map[int]int)
	cdedata.ValidationDelayMatrix[newid] = make(map[int]int)
	cdedata.WriteDelayMatrix[newid] = make(map[int]int)
	cdedata.HashDelayMatrix[newid] = make(map[int]int)
	for k,v := range jtx.Measureres.ProposeDealy {
		cdedata.ProposeDelayMatrix[newid][k] = v
	}
	for k,v := range jtx.Measureres.ValidateDelay {
		cdedata.ValidationDelayMatrix[newid][k] = v
	}
	for k,v := range jtx.Measureres.WriteDelay {
		cdedata.WriteDelayMatrix[newid][k] = v
	}
	for k,v := range jtx.Measureres.HashDelay {
		cdedata.HashDelayMatrix[newid][k] = v
	}
	for k,v := range jtx.InvMeasureres.ProposeDealy {
		cdedata.ProposeDelayMatrix[k][newid] = v
	}
	for k,v := range jtx.InvMeasureres.ValidateDelay {
		cdedata.ValidationDelayMatrix[k][newid] = v
	}
	for k,v := range jtx.InvMeasureres.WriteDelay {
		cdedata.WriteDelayMatrix[k][newid] = v
	}
	for k,v := range jtx.Measureres.HashDelay {
		cdedata.HashDelayMatrix[k][newid] = v
	}
	cdedata.ProposeDelayMatrix[newid][newid] = 0
	cdedata.ValidationDelayMatrix[newid][newid] = 0
	cdedata.WriteDelayMatrix[newid][newid] = 0
	cdedata.HashDelayMatrix[newid][newid] = 0

	cdedata.Round = 1
	fmt.Println("reset cdedata round to 1!")

}

func (cdedata *CDEdata) GeneratePureDelayData() CDEPureDelayData {
	cdep := CDEPureDelayData{}
	cdep.ProposeDelayMatrix = make(map[int]map[int]int)
	cdep.ValidationDelayMatrix = make(map[int]map[int]int)
	cdep.WriteDelayMatrix = make(map[int]map[int]int)
	cdep.HashDelayMatrix = make(map[int]map[int]int)

	for _,v := range cdedata.Peers {
		cdep.ProposeDelayMatrix[v] = make(map[int]int)
		cdep.ValidationDelayMatrix[v] = make(map[int]int)
		cdep.WriteDelayMatrix[v] = make(map[int]int)
		cdep.HashDelayMatrix[v] = make(map[int]int)

		cdep.ProposeDelayMatrix[v] = cdedata.ProposeDelayMatrix[v]
		cdep.ValidationDelayMatrix[v] = cdedata.ValidationDelayMatrix[v]
		cdep.WriteDelayMatrix[v] = cdedata.WriteDelayMatrix[v]
		cdep.HashDelayMatrix[v] = cdedata.HashDelayMatrix[v]
	}

	cdep.Sanitizationflag = cdedata.Sanitizationflag
	return cdep
}

func (cdedata *CDEdata) UpdateUsingPureDelayData(cdep CDEPureDelayData) {
	cdedata.mu.Lock()
	defer cdedata.mu.Unlock()

	for _, u := range cdedata.Peers {
		for _, v := range cdedata.Peers {
			cdedata.ProposeDelayMatrix[u][v] = cdep.ProposeDelayMatrix[u][v]
			cdedata.ValidationDelayMatrix[u][v] = cdep.ValidationDelayMatrix[u][v]
			cdedata.WriteDelayMatrix[u][v] = cdep.WriteDelayMatrix[u][v]
			cdedata.HashDelayMatrix[u][v] = cdep.HashDelayMatrix[u][v]
		}
	}
	cdedata.Sanitizationflag = cdep.Sanitizationflag
}

func (cdedata *CDEdata) FetchTxBatch(txs []Transaction) {
	cdedata.mu.Lock()
	defer cdedata.mu.Unlock()

	cdedata.Txbatch = txs
}

func (cdedata *CDEdata) TxListValidateMultiThread(txlist []Transaction) bool {
	ThreadNum := 2 // Thread number for tx validation
	results := make([]*bool, 0)
	for i:=0; i<ThreadNum; i++ {
		res := new(bool)
		*res = true
		results = append(results, res)
	}

	wg := new(sync.WaitGroup)
	wg.Add(ThreadNum)
	startpos := 0
	distance := len(txlist)/ThreadNum
	for i:=0; i<ThreadNum; i++ {
		txbatch := make([]Transaction, 0)
		if i<ThreadNum-1 {
			txbatch = txlist[startpos:(startpos+distance)]
		} else {
			txbatch = txlist[startpos:len(txlist)]
		}
		go cdedata.TxBatchValidate(txbatch, wg, results[i])
		startpos = startpos + distance
	}
	wg.Wait()

	validateres := true
	for i:=0; i<ThreadNum; i++ {
		if !(*results[i]) {
			validateres = false
		}
	}

	return validateres
}

func (cdedata *CDEdata) TxBatchValidate(txlist []Transaction, wg *sync.WaitGroup, res *bool) {
	for _, tx := range txlist {
		if !tx.Verify(cdedata.Clientacctopuk[tx.Source]) {
			*res = false
			wg.Done()
		}
	}
	*res = true
	wg.Done()
}