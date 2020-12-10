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
	WriteDelayMatrix map[int]map[int]int
	ValidationDelayMatrix map[int]map[int]int

	sanitizationflag map[int]bool

	SendCh chan DatatosendWithIp
	BroadcastCh chan Datatosend
	RecvTestCh chan DataReceived
	RecvResponseCh chan DataReceived

	RecvProposeResponWoCh chan DataReceived
	RecvProposeResponWCh chan DataReceived
	RecvWriteResponCh chan DataReceived

	RecvProposeResponWoFromOldCh chan DataReceived
	RecvProposeResponWFromOldCh chan DataReceived
	RecvWriteResponFromOldCh chan DataReceived

	RecvProposeResponWoFromNewCh chan DataReceived
	RecvProposeResponWFromNewCh chan DataReceived
	RecvWriteResponFromNewCh chan DataReceived

	RecvInformTestCh chan RequestTestMsg
	RecvSingleMeasurement chan SingleMeasurementAToB

	Recvmu sync.Mutex // what for?

	Pubkeystr string
	Prvkey *ecdsa.PrivateKey
	Clientacctopuk map[string]string
}

type CDEPureDelayData struct {

	ProposeDelayMatrix map[int]map[int]int
	WriteDelayMatrix map[int]map[int]int
	ValidationDelayMatrix map[int]map[int]int
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
	cde.sanitizationflag = make(map[int]bool)
	le := len(peers)
	for _,v := range peers {
		cde.Peers = append(cde.Peers, v)
		cde.ProposeDelayMatrix[v] = make(map[int]int)
		cde.WriteDelayMatrix[v] = make(map[int]int)
		cde.ValidationDelayMatrix[v] = make(map[int]int)
		for i:=0; i<le; i++ {
			cde.ProposeDelayMatrix[v][i] = MAXWAITTIME
			cde.WriteDelayMatrix[v][i] = MAXWAITTIME
			cde.ValidationDelayMatrix[v][i] = MAXWAITTIME
		}
	}

	cde.Round = 1
	cde.SendCh = sendch
	cde.BroadcastCh = broadCh
	cde.RecvTestCh = recvtestch
	cde.RecvResponseCh = recvresponsech
	cde.RecvProposeResponWoCh = make(chan DataReceived)
	cde.RecvProposeResponWCh = make(chan DataReceived)
	cde.RecvWriteResponCh = make(chan DataReceived)

	cde.RecvProposeResponWoFromOldCh = make(chan DataReceived)
	cde.RecvProposeResponWFromOldCh = make(chan DataReceived)
	cde.RecvWriteResponFromOldCh = make(chan DataReceived)

	cde.RecvProposeResponWoFromNewCh = make(chan DataReceived)
	cde.RecvProposeResponWFromNewCh = make(chan DataReceived)
	cde.RecvWriteResponFromNewCh = make(chan DataReceived)

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
		//le := len(tmp)
		//theipprefix := tmp[0:(le-1)]
		//theremoteip := theipprefix + strconv.Itoa(cdedata.Id)
		//destip = append(destip, theremoteip)
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
	// validate txlist, it may took some time
	reslist := make([]bool, 0)
	//for _, tx := range proposetestmsg.TxBatch {
	//	reslist = append(reslist, tx.Verify(cdedata.Clientacctopuk[tx.Source]))
	//}

	cdedata.TxListValidateMultiThread(proposetestmsg.TxBatch)

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

func (cdedata *CDEdata) responseWrite(writetestmsg WriteTestMsg, replytonew bool) {
	wrrmsg := NewWriteResponseMsg(cdedata.Id, writetestmsg.Round, writetestmsg.Challange)
	var buff bytes.Buffer
	gob.Register(elliptic.P256())
	enc := gob.NewEncoder(&buff)
	err := enc.Encode(wrrmsg)
	if err != nil {
		log.Panic(err)
	}
	content := buff.Bytes()

	if replytonew {
		// calculate the port number of itself
		destip := make([]string, 0)
		tmp := writetestmsg.IpAddr
		//le := len(tmp)
		//theipprefix := tmp[0:(le-1)]
		//theremoteip := theipprefix + strconv.Itoa(cdedata.Id)
		//destip = append(destip, theremoteip)
		destip = append(destip, tmp)
		datatosend := DatatosendWithIp{destip, "writeresponfromold", content}
		cdedata.SendCh <- datatosend
		//fmt.Println("instance", cdedata.Id, "respond to write-test from new node ip", theremoteip)
	} else {
		dest := make([]int, 0)
		dest = append(dest, writetestmsg.Tester)
		datatosend := Datatosend{dest, "writerespon", content}
		cdedata.BroadcastCh <- datatosend
	}
}

func (cdedata *CDEdata) CDETestMonitor() {
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
				go cdedata.responseWrite(writetest, false)
			case "proposetestfromnew":
				var proposetest ProposeTestMsg
				proposetest.Deserialize(thetest.Msg)
				go cdedata.responseProposeWoValidate(proposetest, true)
				go cdedata.responseProposeWithValidate(proposetest, true)
			case "writetestfromnew":
				var writetest WriteTestMsg
				writetest.Deserialize(thetest.Msg)
				go cdedata.responseWrite(writetest, true)
			case "proposetestfromold":
				var proposetest ProposeTestMsg
				proposetest.Deserialize(thetest.Msg)
				go cdedata.responseProposeWoValidate(proposetest, false)
				go cdedata.responseProposeWithValidate(proposetest, false)
			case "writetestfromold":
				var writetest WriteTestMsg
				writetest.Deserialize(thetest.Msg)
				//fmt.Println("instance", cdedata.Id, "receives a write-test from old instance")
				go cdedata.responseWrite(writetest, false)
			}
		}
	}
}

func (cdedata *CDEdata) CDEResponseMonitor(closeCh chan bool) {
theloop:
	for {
		select {
		case theresponse :=<- cdedata.RecvResponseCh:
			switch theresponse.MsgType {
			case "proporesponwo":
				//fmt.Println("instance", cdedata.Id, "receives a propose-response-wo instance")
				cdedata.RecvProposeResponWoCh <- theresponse
				//fmt.Println("instance", cdedata.Id, "receives a propose-response-wo and sends it to channel")
			case "proporesponw":
				cdedata.RecvProposeResponWCh <- theresponse
			case "writerespon":
				//fmt.Println("instance", cdedata.Id, "receives a write-response, instance")
				cdedata.RecvWriteResponCh <- theresponse
				//fmt.Println("instance", cdedata.Id, "receives a write-response and sended it to channel")
			case "proporesponwofromnew":
				cdedata.RecvProposeResponWoFromNewCh <- theresponse
			case "proporesponwfromnew":
				cdedata.RecvProposeResponWFromNewCh <- theresponse
			case "writeresponfromnew":
				cdedata.RecvWriteResponFromNewCh <- theresponse
			case "proporesponwofromold":
				cdedata.RecvProposeResponWoFromOldCh <- theresponse
			case "proporesponwfromold":
				cdedata.RecvProposeResponWFromOldCh <- theresponse
			case "writeresponfromold":
				cdedata.RecvWriteResponFromOldCh <- theresponse
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
	//fmt.Println("instance ", cdedata.Id, " starts full testing for new instance", reqtest.Testee)
	testee := reqtest.Testee
	testeeip := reqtest.IpAddr
	delays := make([]int, 0)
	for i:=0; i<3; i++ {
		delays = append(delays, MAXWAITTIME)
	}
	dests := make([]string, 0)
	dests = append(dests, testeeip)

	// ------------------------------------------------------- test write self->new
	// pack a write-test message
	rann := uint64(time.Now().Unix())
	wrmsg := NewWriteMsg(cdedata.Id, cdedata.Round, cdedata.IpAddr, rann)
	starttime1 := time.Now()

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

	closed := make(chan bool)
	cdedata.Recvmu.Lock()
	go cdedata.CDEResponseMonitor(closed)

	// block, wait for response
	thetimer := time.NewTimer(time.Millisecond * MAXWAITTIME)
	theloop1:
	for {
		select {
		case <-thetimer.C:
			break theloop1
		case theresponse := <- cdedata.RecvWriteResponCh:
			var wrr WriteResponseMsg
			wrr.Deserialize(theresponse.Msg)
			if wrr.Testee==testee && wrr.Challange==rann {
				delays[0] = int(time.Since(starttime1).Milliseconds()/2)
				//fmt.Println("instance", cdedata.Id, "measure write-delay to new instance: ", cdedata.Id, " --> ", testee, ":", delays[0])
				break theloop1
			}
		}
	}

	// ------------------------------------------------------- test propose self->new and validate self->new
	// pack a propose-test message
	rann = uint64(time.Now().Unix())
	ppmsg := NewProposeMsg(cdedata.Id, cdedata.Round, cdedata.IpAddr, []Transaction{}, rann)
	starttime2 := time.Now()
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
	t1 := 0
	thetimer = time.NewTimer(time.Millisecond * MAXWAITTIME)

	theloop2:
	for {
		select {
		case <-thetimer.C:
			break theloop2
		case theresponse :=<- cdedata.RecvProposeResponWoCh:
			var ppr ProposeResponseWoValidateMsg
			ppr.Deserialize(theresponse.Msg)
			if ppr.Round==cdedata.Round && ppr.Challange==rann {
				t1 = int(time.Since(starttime2).Milliseconds())
				delays[1] = t1 - delays[0]
				//fmt.Println("instance", cdedata.Id, "measure propose-delay to new instance: ", cdedata.Id, "--> ", testee, ":", delays[1])
			} else {
				//fmt.Println("isntance", cdedata.Id, "wrong measures propose-delay, ", cdedata.Id, " --> ", testee, ":", delays[1])
			}
		case theresponse :=<- cdedata.RecvProposeResponWCh:
			var ppr ProposeResponseWithValidateMsg
			ppr.Deserialize(theresponse.Msg)
			if ppr.Round==cdedata.Round && ppr.Challange==rann {
				delays[2] = int(time.Since(starttime2).Milliseconds()) - t1
				//fmt.Println("instance", cdedata.Id, "measure validate-delay to new instance: ", cdedata.Id, "--> ", testee, ":", delays[2])
			}
		}
	}

	closed <- true
	cdedata.Recvmu.Unlock()



	// ------------------------------------------------------- send test res to new
	smmsg := NewSingleMeasurement(cdedata.Id, testee, delays, cdedata.Pubkeystr, cdedata.Prvkey)
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
		if mrr.ProposeFlag {
			cdedata.ProposeDelayMatrix[tester] = mrr.ProposeDealy
			cdedata.ValidationDelayMatrix[tester] = mrr.ValidateDelay
		}
		cdedata.WriteDelayMatrix[tester] = mrr.WriteDelay
		cdedata.sanitizationflag[tester] = true
	}

	sanitize := false
	for _, id := range cdedata.Peers {
		if cdedata.sanitizationflag[id] == false {
			break
		}
	}
	if sanitize {
		cdedata.Sanitization()
	}
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
	tmp1 := append(cdedata.Peers, proposetwodlistrepresent...)
	tmp2 := append(tmp1, validatetwodlistrepresent...)
	thefinallist := append(tmp2, writetwodlistrepresent...)

	var content []byte
	for _,v := range thefinallist {
		EncodeInt(&content, v)
	}
	hashv := sha256.Sum256(content)
	return hashv
}

func (cdedata *CDEdata) CollectDelayDataForNew(txbatch []Transaction) JoinTx {

	//// update write new->system
	fmt.Println("new instance starts update write-delay new --> system")
	closech := make(chan bool)
	go cdedata.CDEResponseMonitor(closech)
	delayv := cdedata.CreateDelayVector(txbatch)
	//
	delayv.UpdateAtNew("write")
	//delayv.PrintResult()
	closech<-true
	//fmt.Println("new instance updates write-delay completes-----------------------------------------------------------------------------------------------------")


	// for node in system: update node->new one by one
	go cdedata.CDETestMonitor()
	inverseproposedelay := make(map[int]int)
	inversevalidatedelay := make(map[int]int)
	inversewritedelay := make(map[int]int)
	for _, i := range cdedata.Peers {
		// inform instance i to test itself
		singlemmsg := cdedata.InformTestInstance(cdedata.Id, i) // block, until receives the test result with signature
		inverseproposedelay[i] = singlemmsg.Proposedelay
		inversevalidatedelay[i] = singlemmsg.Validatedelay
		inversewritedelay[i] = singlemmsg.Writedelay
	}
	imrmsg := NewInverseMeasurementResultMsg(cdedata.Id, cdedata.Round, cdedata.Peers, inverseproposedelay,
		inversevalidatedelay, inversewritedelay, cdedata.Pubkeystr, cdedata.Prvkey)
	//fmt.Println("inverse propose-delay is", inverseproposedelay)
	//fmt.Println("inverse validate-delay is", inversevalidatedelay)
	//fmt.Println("inverse write-delay is", inversewritedelay)

	// update propose new->sytem
	go cdedata.CDEResponseMonitor(closech)
	delayv.UpdateAtNew("propose")
	delayv.PrintResult()
	closech<-true
	mrmsg := NewMeasurementResultMsg(cdedata.Id, cdedata.Round, cdedata.Peers, delayv.ProposeDelaydata,
		delayv.WriteDelaydata, delayv.ValidationDelaydata, true, cdedata.Pubkeystr, cdedata.Prvkey)

	// create join-tx for new instance
	fmt.Println("new instance creates join-tx")
	jtx := NewJoinTx(cdedata.Id, cdedata.IpAddr, mrmsg, imrmsg, cdedata.Pubkeystr, cdedata.Prvkey)
	return jtx
}

func (cdedata *CDEdata) InformTestInstance(id int, dest int) SingleMeasurementAToB {
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


	blockdelay := cdedata.ProposeDelayConvertToMatrix()
	validatedelay := cdedata.ValidationDelayConverToMatrix()
	votedelay := cdedata.WriteDelayConvertToMatrix()

	Time_recv_pre_prepare := make([]int, N)
	Time_recv_prepare := make([][]int, N)
	Time_recv_commit := make([][]int, N)
	Time_prepare := make([]int, N)
	Time_commit := make([]int, N)

	for i:=0; i<N; i++ {
		Time_recv_pre_prepare[i] = blockdelay[l][i] + validatedelay[l][i]
		for i:=0; i<N; i++ {
			Time_recv_prepare[i] = make([]int, N)
		}
		for i:=0; i<N; i++ {
			Time_recv_commit[i] = make([]int, N)
		}
	}

	for i:=0; i<N; i++ {
		for j:=0; j<N; j++ {
			Time_recv_prepare[i][j] = Time_recv_pre_prepare[j]+blockdelay[j][i]
		}
		sort.Ints(Time_recv_prepare[i])
	}

	for i:=0; i<N; i++ {
		Time_prepare[i] = Time_recv_prepare[i][Q-1]
	}

	for i:=0; i<N; i++ {
		for j:=0; j<N; j++ {
			Time_recv_commit[i][j] = Time_prepare[j]+votedelay[j][i]
		}
		sort.Ints(Time_recv_commit[i])
	}

	for i:=0; i<N; i++ {
		Time_commit[i] = Time_recv_commit[i][Q-1]
	}

	return Time_commit
}

func (cdedata *CDEdata) CalculateConsensusDelayForNewJointx(l, N, Q int, jtx JoinTx) []int {
	cdedata.mu.Lock()
	defer cdedata.mu.Unlock()

	newcdedata := cdedata.CopyData()
	newcdedata.AddNewInstanceData(jtx)
	//newcdedata.Sanitization()

	blockdelay := newcdedata.ProposeDelayConvertToMatrix()
	validatedelay := newcdedata.ValidationDelayConverToMatrix()
	votedelay := newcdedata.WriteDelayConvertToMatrix()

	Time_recv_pre_prepare := make([]int, N)
	Time_recv_prepare := make([][]int, N)
	Time_recv_commit := make([][]int, N)
	Time_prepare := make([]int, N)
	Time_commit := make([]int, N)

	for i:=0; i<N; i++ {
		Time_recv_pre_prepare[i] = blockdelay[l][i] + validatedelay[l][i]
		for i:=0; i<N; i++ {
			Time_recv_prepare[i] = make([]int, N)
		}
		for i:=0; i<N; i++ {
			Time_recv_commit[i] = make([]int, N)
		}
	}

	for i:=0; i<N; i++ {
		for j:=0; j<N; j++ {
			Time_recv_prepare[i][j] = Time_recv_pre_prepare[j]+blockdelay[j][i]
		}
		sort.Ints(Time_recv_prepare[i])
	}

	for i:=0; i<N; i++ {
		Time_prepare[i] = Time_recv_prepare[i][Q-1]
	}

	for i:=0; i<N; i++ {
		for j:=0; j<N; j++ {
			Time_recv_commit[i][j] = Time_prepare[j]+votedelay[j][i]
		}
		sort.Ints(Time_recv_commit[i])
	}

	for i:=0; i<N; i++ {
		Time_commit[i] = Time_recv_commit[i][Q-1]
	}

	return Time_commit
}

func (cdedata *CDEdata) CopyData() CDEdata {
	newcdedata := CDEdata{}
	newcdedata.Id = cdedata.Id
	newcdedata.IpAddr = cdedata.IpAddr
	newcdedata.Peers = cdedata.Peers

	newcdedata.ProposeDelayMatrix = make(map[int]map[int]int)
	newcdedata.ValidationDelayMatrix = make(map[int]map[int]int)
	newcdedata.WriteDelayMatrix = make(map[int]map[int]int)

	for _,v := range newcdedata.Peers {
		newcdedata.ProposeDelayMatrix[v] = make(map[int]int)
		newcdedata.WriteDelayMatrix[v] = make(map[int]int)
		newcdedata.ValidationDelayMatrix[v] = make(map[int]int)

		newcdedata.ProposeDelayMatrix[v] = cdedata.ProposeDelayMatrix[v]
		newcdedata.ValidationDelayMatrix[v] = cdedata.ValidationDelayMatrix[v]
		newcdedata.WriteDelayMatrix[v] = cdedata.WriteDelayMatrix[v]
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
		}
	}
}

func (cdedata *CDEdata) AddNewInstanceData(jtx JoinTx) {
	newid := jtx.Id
	cdedata.Peers = append(cdedata.Peers, newid)
	cdedata.ProposeDelayMatrix[newid] = make(map[int]int)
	cdedata.ValidationDelayMatrix[newid] = make(map[int]int)
	cdedata.WriteDelayMatrix[newid] = make(map[int]int)
	for k,v := range jtx.Measureres.ProposeDealy {
		cdedata.ProposeDelayMatrix[newid][k] = v
	}
	for k,v := range jtx.Measureres.ValidateDelay {
		cdedata.ValidationDelayMatrix[newid][k] = v
	}
	for k,v := range jtx.Measureres.WriteDelay {
		cdedata.WriteDelayMatrix[newid][k] = v
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
	cdedata.ProposeDelayMatrix[newid][newid] = 0
	cdedata.ValidationDelayMatrix[newid][newid] = 0
	cdedata.WriteDelayMatrix[newid][newid] = 0
}

func (cdedata *CDEdata) GeneratePureDelayData() CDEPureDelayData {
	cdep := CDEPureDelayData{}
	cdep.ProposeDelayMatrix = make(map[int]map[int]int)
	cdep.ValidationDelayMatrix = make(map[int]map[int]int)
	cdep.WriteDelayMatrix = make(map[int]map[int]int)

	for _,v := range cdedata.Peers {
		cdep.ProposeDelayMatrix[v] = make(map[int]int)
		cdep.ValidationDelayMatrix[v] = make(map[int]int)
		cdep.WriteDelayMatrix[v] = make(map[int]int)

		cdep.ProposeDelayMatrix[v] = cdedata.ProposeDelayMatrix[v]
		cdep.ValidationDelayMatrix[v] = cdedata.ValidationDelayMatrix[v]
		cdep.WriteDelayMatrix[v] = cdedata.WriteDelayMatrix[v]
	}
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
		}
	}
}


func (cdedata *CDEdata) TxListValidateMultiThread(txlist []Transaction) bool {
	ThreadNum := 4 // Thread number for tx validation
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