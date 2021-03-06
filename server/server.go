package server

import (
	"../datastruc"
	"../pbft"
	"bufio"
	"bytes"
	"crypto/elliptic"
	"crypto/sha256"
	b64 "encoding/base32"
	"encoding/binary"
	"encoding/gob"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"sync"
	"time"
)

type Server struct {
	mu           sync.Mutex
	decoderrortx int
	sigwrongtx   int
	repeattx     int
	starttime    time.Time

	id                   int
	ipportaddr           string
	localallipsforserver []string // receives servers' messages from these ports
	localallipsforclient []string // receives clients' messages from these ports

	totalserver  int
	memberIds    []int
	remoteallips map[int]string // ip addresses this server will send message to

	msgbuff           datastruc.MessageBuffer
	pbft              *pbft.PBFT
	clientacctopukstr map[string]string

	sendCh               chan datastruc.DatatosendWithIp
	broadcastCh          chan datastruc.Datatosend
	memberidchangeCh     chan datastruc.DataMemberChange
	censorshipmonitorCh  chan [32]byte
	statetransferqueryCh chan datastruc.QueryStateTransMsg
	statetransferreplyCh chan datastruc.ReplyStateTransMsg
	cdetestrecvCh        chan datastruc.DataReceived
	cderesponserecvCh    chan datastruc.DataReceived

	RecvInformTestCh        chan datastruc.RequestTestMsg
	recvsinglemeasurementCh chan datastruc.SingleMeasurementAToB

	stopCh chan bool

	recvconfigCh      chan datastruc.ReadConfigReply
	bytesended        int
	byterecvfserver   int
	byterecvfclient   int
	blockvalidatetime map[int]int
}

func CreateServer(id int, localip string, clientpukstr map[int]string, serverips []string, inseach int) *Server {
	serv := &Server{}

	serv.starttime = time.Now()
	serv.id = id
	serv.ipportaddr = localip + ":4" + datastruc.GenerateTwoBitId(id) + "0"
	serv.totalserver = len(serverips) * inseach
	for i := 0; i < serv.totalserver; i++ {
		serv.memberIds = append(serv.memberIds, i)
	}
	serv.InitializeMapandChan()
	serv.remoteallips = generateremoteallips(serv.memberIds, serverips, inseach) // including the ip of itself
	fmt.Println("server", serv.id, "will send consensus messages to", serv.remoteallips)
	serv.localallipsforserver = generatelistenserverips(id, localip)
	serv.localallipsforclient = generatelistenclientips(id, localip)
	serv.msgbuff = datastruc.MessageBuffer{}
	serv.msgbuff.Initialize()

	for _, v := range clientpukstr {
		hv := sha256.Sum256([]byte(v))
		acc := b64.StdEncoding.EncodeToString(hv[:])
		serv.clientacctopukstr[acc] = v
	}

	serv.pbft = pbft.CreatePBFTInstance(id, serv.ipportaddr, serv.totalserver, clientpukstr, &serv.msgbuff, serv.starttime,
		serv.sendCh, serv.broadcastCh, serv.memberidchangeCh,
		serv.censorshipmonitorCh, serv.statetransferqueryCh, serv.statetransferreplyCh, serv.cdetestrecvCh,
		serv.cderesponserecvCh, serv.RecvInformTestCh, serv.recvsinglemeasurementCh, serv.stopCh)
	return serv
}

func CreateLateServer(id int, localip string, clientpukstr map[int]string, initialserverips []string, inseach int) *Server {
	serv := &Server{}

	serv.starttime = time.Now()
	serv.id = id
	serv.InitializeMapandChan()
	serv.ipportaddr = localip + ":4" + datastruc.GenerateTwoBitId(id) + "0"
	//serv.totalserver = len(initialserverips) * inseach // total server does not count itself
	serv.localallipsforserver = generatelistenserverips(id, localip)
	serv.localallipsforclient = generatelistenclientips(id, localip)
	serv.msgbuff = datastruc.MessageBuffer{}
	serv.msgbuff.Initialize()

	for _, v := range clientpukstr {
		hv := sha256.Sum256([]byte(v))
		acc := b64.StdEncoding.EncodeToString(hv[:])
		serv.clientacctopukstr[acc] = v
	}
	// total number, read from config
	// memberid, read from config
	// remoteallips, read from config
	// create pbft instance
	return serv
}

func (serv *Server) InitializeMapandChan() {
	serv.clientacctopukstr = make(map[string]string)
	serv.remoteallips = make(map[int]string)

	serv.sendCh = make(chan datastruc.DatatosendWithIp)
	serv.broadcastCh = make(chan datastruc.Datatosend)
	serv.memberidchangeCh = make(chan datastruc.DataMemberChange)
	serv.censorshipmonitorCh = make(chan [32]byte)
	serv.statetransferqueryCh = make(chan datastruc.QueryStateTransMsg)
	serv.statetransferreplyCh = make(chan datastruc.ReplyStateTransMsg)
	serv.cdetestrecvCh = make(chan datastruc.DataReceived)
	serv.cderesponserecvCh = make(chan datastruc.DataReceived)
	serv.RecvInformTestCh = make(chan datastruc.RequestTestMsg)
	serv.recvsinglemeasurementCh = make(chan datastruc.SingleMeasurementAToB)
	serv.recvconfigCh = make(chan datastruc.ReadConfigReply)
	serv.stopCh = make(chan bool)
	serv.blockvalidatetime = make(map[int]int)
}

func (serv *Server) Start() {
	go serv.Run()

	time.Sleep(time.Second * 1)
	serv.pbft.InitialSetup()
	time.Sleep(time.Second * 5)
	go serv.pbft.Run()
}

func (serv *Server) LateStart(clientkeys map[int]string, sleeptime int) {
	go serv.Run()

	time.Sleep(time.Second * time.Duration(sleeptime))
	fmt.Println("the late server", serv.id, "reads config from some remote peer:")
	peerlist := serv.ReadConfigFromRemote()
	fmt.Println("server", serv.id, "readConfigFromRemote completes, peerlist: ", peerlist)
	serv.totalserver = len(peerlist) + 1
	for _, v := range peerlist {
		serv.memberIds = append(serv.memberIds, v.Id)
		serv.remoteallips[v.Id] = v.IpPortAddr
	}
	serv.memberIds = append(serv.memberIds, serv.id)
	serv.remoteallips[serv.id] = serv.ipportaddr // add itself to members
	fmt.Println("server", serv.id, "remote all ips:", serv.remoteallips)
	serv.pbft = pbft.CreatePBFTInstance(serv.id, serv.ipportaddr, serv.totalserver, clientkeys, &serv.msgbuff, serv.starttime,
		serv.sendCh, serv.broadcastCh, serv.memberidchangeCh, serv.censorshipmonitorCh, serv.statetransferqueryCh,
		serv.statetransferreplyCh, serv.cdetestrecvCh, serv.cderesponserecvCh, serv.RecvInformTestCh, serv.recvsinglemeasurementCh,
		serv.stopCh)

	start := time.Now()
	serv.pbft.LateSetup(peerlist)
	elapsed1 := time.Since(start).Milliseconds()
	elpased2 := time.Since(serv.starttime).Milliseconds()
	fmt.Println("the new instance late setup completes, time costs", int(elapsed1), "ms, start consensing at", elpased2, "ms")
	go serv.pbft.Run()
}

func (serv *Server) Run() {
	// a replica/server will listen 70 local ports, the first 10 (for pbft instance) will on normal mode,
	// the latter 60 (for client) will on long-connection to receive tx from clients
	for _, localipport := range serv.localallipsforserver {
		go serv.ListenLocalForServer(localipport)
	}
	for _, localipport := range serv.localallipsforclient {
		go serv.ListenLocalForClient(localipport)
	}
	go serv.BroadcastLoop()
	go serv.SendLoop()
	go serv.ModefyVariByPBFT()
}

func (serv *Server) ModefyVariByPBFT() {
	for {
		select {
		case data := <-serv.memberidchangeCh:
			serv.mu.Lock()
			if data.Kind == "join" {
				serv.memberIds = append(serv.memberIds, data.Id)
				serv.remoteallips[data.Id] = data.IpPortAddr
				fmt.Println("server", serv.id, "adds instance", data.Id, "'s ip, now has", len(serv.memberIds), "remote address to communicate")
			} else if data.Kind == "leave" {
				tmp := make([]int, 0)
				for i := 0; i < len(serv.memberIds); i++ {
					if serv.memberIds[i] != data.Id {
						tmp = append(tmp, serv.memberIds[i])
					}
				}
				serv.memberIds = tmp
				fmt.Println("server", serv.id, "delete an instance's ip, now has", len(serv.memberIds), "remote address to communicate")
			} else {
				fmt.Println("server", serv.id, "got wrong type when changing state!")
			}
			serv.mu.Unlock()
		}
	}
}

func (serv *Server) ListenLocalForServer(localipport string) {
	listener, err := net.Listen(protocol, localipport)

	if err != nil {
		fmt.Printf("net.Listen() runs wrongly :%v\n", err)
		return
	}
	defer listener.Close()
	for true {
		conn, err := listener.Accept()

		if err != nil {
			fmt.Printf("listener.Accept() runs wrongly in ListenLocalForServer:%v\n", err)
			fmt.Println("time: ", time.Since(serv.starttime).Seconds(), "s")
			return
		}
		defer conn.Close()
		request, err := ioutil.ReadAll(conn)
		commanType := datastruc.BytesToCommand(request[:commandLength])
		//fmt.Println("the message type is ", commanType)
		if err != nil {
			log.Panic(err)
		}
		serv.byterecvfserver += len(request)
		switch commanType {
		case "idportpubkey":
			go serv.handleIdPortPubkey(request[commandLength:])
		case "jointx":
			go serv.handleJoinTx(request[commandLength:])
		case "leavetx":
			go serv.handleLeaveTx(request[commandLength:])
		case "txblock":
			go serv.handleBlock(request[commandLength:])
		case "configblock":
			go serv.handleBlock(request[commandLength:])
		case "confirmedblock":
			go serv.handleConfirmedBlock(request[commandLength:])
		case "checkpointmsg":
			go serv.handleCheckpointMsg(request[commandLength:])
		case "prepreparemsg":
			go serv.handlePreprepareMsg(request[commandLength:])
		case "preparemsg":
			go serv.handlePrepareMsg(request[commandLength:])
		case "commitmsg":
			go serv.handleCommitMsg(request[commandLength:])
		case "viewchangemsg":
			go serv.handleViewChangeMsg(request[commandLength:])
		case "newviewmsg":
			go serv.handleNewViewMsg(request[commandLength:])
		case "querystatetran":
			go serv.handleStateTransferQuery(request[commandLength:])
		case "replystatetran":
			go serv.handleStateTransferReply(request[commandLength:])
		case "proposetest":
			go serv.handleProposeTest(request[commandLength:])
		case "writetest":
			go serv.handleWriteTest(request[commandLength:])
		case "proposetestfromnew":
			go serv.handleProposeTestFromNew(request[commandLength:])
		case "writetestfromnew":
			go serv.handleWriteTestFromNew(request[commandLength:])
		case "proposetestfromold":
			go serv.handleProposeTestFromOld(request[commandLength:])
		case "writetestfromold":
			go serv.handleWriteTestFromOld(request[commandLength:])
		case "proporesponwo":
			go serv.handleProposeResponseWoValidate(request[commandLength:])
		case "proporesponw":
			go serv.handleProposeResponseWithValidate(request[commandLength:])
		case "writeresponwo":
			go serv.handleWriteResponseWoHash(request[commandLength:])
		case "writeresponw":
			go serv.handleWriteResponseWithHash(request[commandLength:])
		case "proporesponwofromold":
			go serv.handleProposeResponseWoValidateFromOld(request[commandLength:])
		case "proporesponwfromold":
			go serv.handleProposeResponseWithValidateFromOld(request[commandLength:])
		case "writeresponwofromold":
			go serv.handleWriteResponseWoHashFromOld(request[commandLength:])
		case "writeresponwfromold":
			go serv.handleWriteResponseWithHashFromOld(request[commandLength:])
		case "proporesponwofromnew":
			go serv.handleProposeResponseWoValidateFromNew(request[commandLength:])
		case "proporesponwfromnew":
			go serv.handleProposeResponseWithValidateFromNew(request[commandLength:])
		case "writeresponwofromnew":
			go serv.handleWriteResponseWoHashFromNew(request[commandLength:])
		case "writeresponwfromnew":
			go serv.handleWriteResponseWithHashFromNew(request[commandLength:])
		case "measurement":
			go serv.handleMeasurementRes(request[commandLength:])
		case "singlemeasurement":
			go serv.handleSingleMeasurement(request[commandLength:])
		case "informtest":
			go serv.handleInformTest(request[commandLength:])
		case "readconfig":
			//fmt.Println("server", serv.id, "receives a read config request")
			go serv.handleReadConfigRequest(request[commandLength:])
		case "readconfigreply":
			//fmt.Println("server", serv.id, "receives a read config reply")
			go serv.handleReadConfigReply(request[commandLength:])
		}
	}
}

func (serv *Server) ListenLocalForClient(localipport string) {
	listener, err := net.Listen(protocol, localipport)

	if err != nil {
		fmt.Printf("net.Listen() runs wrongly :%v\n", err)
		return
	}
	defer listener.Close()
	for true {
		conn, err := listener.Accept()

		fmt.Println("server accepts a new tcp connection dial\n")
		if err != nil {
			fmt.Printf("listener.Accept() runs wrongly in ListenLocalForClient:%v\n", err)
			return
		}
		defer conn.Close()
		go serv.handleclienttx(conn)

	}
}

func (serv *Server) BroadcastLoop() {
	// send data according to id, this only applies to closed members in server class.
theloop:
	for {
		select {
		case data := <-serv.broadcastCh:
			for _, i := range data.Destorder {

				request := append(datastruc.CommandToBytes(data.MsgType), data.Msg...)
				serv.mu.Lock()
				if serv.remoteallips[i] != "" {
					sendData(request, serv.remoteallips[i])
					serv.bytesended += len(request)
				} else {
					fmt.Println("not valid destination ip, the dest id is", i)
				}
				serv.mu.Unlock()
			}
		case <-serv.stopCh:
			fmt.Println("server", serv.id, "stops its broadcasting loop, total Bytes send:", serv.bytesended/(1024),
				"KB, total Bytes received from servers:", serv.byterecvfserver/1024, "KB, total Bytes received from clients:",
				serv.byterecvfclient/1024, "KB, total tx with decoding error is", serv.decoderrortx)
			fmt.Println("block validation time:", serv.blockvalidatetime)
			break theloop
		}
	}
}

func (serv *Server) SendLoop() {
	// send data according to ip, this applies to those information from new instances.
theloop:
	for {
		select {
		case data := <-serv.sendCh:
			for _, destip := range data.DestIp {
				request := append(datastruc.CommandToBytes(data.MsgType), data.Msg...)
				sendData(request, destip)
				serv.bytesended += len(request)
			}
		case <-serv.stopCh:
			fmt.Println("server", serv.id, "stops its sending loop")
			break theloop
		}
	}
}

func generatelistenserverips(id int, localip string) []string {
	res := []string{}
	theip := localip + ":4" + datastruc.GenerateTwoBitId(id) + "0"
	res = append(res, theip)
	fmt.Println("server", id, "will listen on", res, "to receive from servers")
	return res
}

func generatelistenclientips(id int, localip string) []string {
	res := []string{}
	theip := localip + ":4" + datastruc.GenerateTwoBitId(id) + "1"
	res = append(res, theip)
	fmt.Println("server", id, "will listen on", res, "to receive from clients")
	return res
}

func generateremoteallips(memberIds []int, serverips []string, inseach int) map[int]string {
	// generate those ips this server will send messages to
	res := make(map[int]string)
	for _, i := range memberIds {
		var theip string
		//if id<10 {
		//	theip = ipprefix + strconv.Itoa(i)
		//} else {
		//	theip = ipprefix + strconv.Itoa(i)
		//}
		var order int
		order = i / inseach
		theip = serverips[order] + ":4" + datastruc.GenerateTwoBitId(i) + "0"
		res[i] = theip
	}
	//fmt.Println("server", id, "will sends msg to", res)
	return res
}

//func generateremoteipfornewid(id int, newid int) string {
//	var theip string
//
//	if id<10 {
//		theip = ipprefix + strconv.Itoa(newid) + "0" + strconv.Itoa(id)
//	} else {
//		theip = ipprefix + strconv.Itoa(newid) + strconv.Itoa(id)
//	}
//	return theip
//}

//func (serv *Server) broadcastMsg(msg interface{}, msgtype string, dest []int) {
//	var buff bytes.Buffer
//	gob.Register(elliptic.P256())
//	enc := gob.NewEncoder(&buff)
//	err := enc.Encode(msg)
//	if err != nil {
//		log.Panic(err)
//	}
//	content := buff.Bytes()
//	comman := datastruc.CommandToBytes(msgtype)
//	content = append(comman, content...)
//	for _, i := range dest {
//		serv.mu.Lock()
//		go sendData(content, serv.remoteallips[i])
//		serv.mu.Unlock()
//	}
//}

//func (serv *Server) sendMsg(msg interface{}, msgtype string, dest int) {
//	var buff bytes.Buffer
//	gob.Register(elliptic.P256())
//	enc := gob.NewEncoder(&buff)
//	err := enc.Encode(msg)
//	if err != nil {
//		log.Panic(err)
//	}
//	content := buff.Bytes()
//	comman := datastruc.CommandToBytes(msgtype)
//	content = append(comman, content...)
//	serv.mu.Lock()
//	go sendData(content, serv.remoteallips[dest])
//	serv.mu.Unlock()
//}

func sendData(data []byte, addr string) {

	conn, err := net.Dial(protocol, addr)

	if err != nil {
		fmt.Printf("%s is not available\n", addr)
	} else {
		defer conn.Close()
		_, err = conn.Write(data)
		if err != nil {
			fmt.Println("send error")
			log.Panic(err)
		}
	}
}

func (serv *Server) handleclienttx(conn net.Conn) {
	defer conn.Close()
	defer fmt.Println("close!!!")
	//fmt.Println("????????????", conn.RemoteAddr())

	result := bytes.NewBuffer(nil)
	var readbuf [4500]byte // ?????? ????????????????????? ????????????????????? ????????????????????? 2^16+4(??????)+2(????????????)
	remains := make([]byte, 0)
	var remainn int
	var readlen int
	mergedbuf := make([]byte, 0)
	for {
		n, err := conn.Read(readbuf[0:])
		serv.byterecvfclient += n
		if n == 0 {
			continue
		}
		//fmt.Println("server read buffer ", n, "bytes, total bytes received is ", serv.recvvolume)

		if remainn > 0 {
			mergedbuf = append(remains, readbuf[0:n]...)
			//fmt.Println("merge remaining bytes: ", remainn, "[]len ", len(remains), "buf length after merge is", len(mergedbuf))
		} else {
			mergedbuf = append([]byte{}, readbuf[0:n]...)
			//fmt.Println("there is no remaining bytes, buf length without merging is", len(mergedbuf))
		}

		result.Write(mergedbuf[0:])
		readlen = 0
		if err != nil {
			if err == io.EOF {
				continue
			} else {
				fmt.Println("read err:", err)
				break
			}
		} else {
			scanner := bufio.NewScanner(result)
			scanner.Split(packetSlitFunc)
			for scanner.Scan() {
				readlen += len(scanner.Bytes())
				go serv.handleTransaction(scanner.Bytes()[6:])
			}
		}
		remainn = len(mergedbuf) - readlen
		remains = make([]byte, remainn)
		copy(remains, mergedbuf[readlen:])

		result.Reset()
	}
}

func packetSlitFunc(data []byte, atEOF bool) (advance int, token []byte, err error) {
	// ?????? atEOF ?????? ??? ???????????????????????????????????? ??? 0x123456(??????????????????????????????)
	if !atEOF && len(data) > 6 && binary.BigEndian.Uint32(data[:4]) == 0x123456 {
		var l int16
		// ?????? ???????????? ???????????? ?????????(????????? 0 ~ 2^16)
		binary.Read(bytes.NewReader(data[4:6]), binary.BigEndian, &l)
		pl := int(l) + 6
		if pl <= len(data) {
			return pl, data[:pl], nil
		}
	}
	return
}

func (serv *Server) handleJoinTx(conten []byte) {
	var buff bytes.Buffer
	var jointx datastruc.JoinTx
	buff.Write(conten)
	dec := gob.NewDecoder(&buff)
	err := dec.Decode(&jointx)
	if err != nil {
		fmt.Println("jointx decoding error")
	}
	serv.msgbuff.Msgbuffmu.Lock()
	serv.msgbuff.JoinLeavetxSet.JTxset = append(serv.msgbuff.JoinLeavetxSet.JTxset, jointx)
	fmt.Println("server", serv.id, "receives a join-tx, the requester is", jointx.Id, "at", time.Since(serv.starttime).Seconds(), "s")
	serv.msgbuff.Msgbuffmu.Unlock()
}

func (serv *Server) handleLeaveTx(conten []byte) {
	var buff bytes.Buffer
	var leavetx datastruc.LeaveTx
	buff.Write(conten)
	gob.Register(elliptic.P256())
	dec := gob.NewDecoder(&buff)
	err := dec.Decode(&leavetx)
	if err != nil {
		fmt.Println("leavetx decoding error")
	}

	if !leavetx.Verify() {
		fmt.Println("server", serv.id, "receives unvalid leave-tx", leavetx)
		return
	} else {
		fmt.Println("server", serv.id, "receives a leave-tx")
	}

	serv.msgbuff.Msgbuffmu.Lock()
	serv.msgbuff.JoinLeavetxSet.LTxSet = append(serv.msgbuff.JoinLeavetxSet.LTxSet, leavetx)
	//fmt.Println("server", serv.id, "receives a leave-tx")
	serv.msgbuff.Msgbuffmu.Unlock()
	serv.censorshipmonitorCh <- leavetx.TxHash
}

func (serv *Server) handleIdPortPubkey(conten []byte) {
	var buff bytes.Buffer
	var peerid datastruc.PeerIdentity
	buff.Write(conten)
	dec := gob.NewDecoder(&buff)
	err := dec.Decode(&peerid)
	if err != nil {
		fmt.Println("addrpubkey decoding error")
	}
	fmt.Println("server", serv.id, "receives a ipportpubkey msg")
	serv.msgbuff.Msgbuffmu.Lock()
	serv.msgbuff.InitialConfig = append(serv.msgbuff.InitialConfig, peerid)
	serv.msgbuff.Msgbuffmu.Unlock()
}

func (serv *Server) handleTransaction(request []byte) {
	conten := request[commandLength:]
	//fmt.Println("server", serv.id, " has receives a tx now")
	var buff bytes.Buffer
	var tx datastruc.Transaction
	buff.Write(conten)
	gob.Register(elliptic.P256())
	dec := gob.NewDecoder(&buff)
	err := dec.Decode(&tx)
	if err != nil {
		serv.decoderrortx += 1
		if serv.decoderrortx%1000 == 0 {
			fmt.Println("server", serv.id, "tx decoding error time:", serv.decoderrortx, "at time", time.Since(serv.starttime), "s")
		}
		return
	}
	serv.msgbuff.Msgbuffmu.Lock()
	if _, ok := serv.msgbuff.TxPool[tx.GetHash()]; ok {
		serv.repeattx += 1
		if serv.repeattx%1000 == 0 {
			fmt.Println("server", serv.id, "repeat tx time:", serv.repeattx)
		}
		serv.msgbuff.Msgbuffmu.Unlock()
		return
	}
	serv.msgbuff.Msgbuffmu.Unlock()

	if tx.Verify(serv.clientacctopukstr[tx.Source]) {
		serv.msgbuff.Msgbuffmu.Lock()
		serv.msgbuff.TxPool[tx.GetHash()] = tx
		//if len(serv.msgbuff.TxPool)%1==0 {
		//	//fmt.Println("server receive 1 txs, the last one with timestamp", tx.Timestamp)
		//	elaps := time.Since(serv.starttime).Milliseconds()
		//	fmt.Println("server", serv.id, "has",len(serv.msgbuff.TxPool), "txs time elapsed: ", elaps, "ms")
		//}
		serv.msgbuff.Msgbuffmu.Unlock()
	} else {
		serv.sigwrongtx += 1
		if serv.sigwrongtx%1000 == 0 {
			fmt.Println("server", serv.id, "receives a tx with wrong signature time:", serv.sigwrongtx)
		}
	}
}

func (serv *Server) handleBlock(content []byte) {
	var buff bytes.Buffer
	var bloc datastruc.Block
	buff.Write(content)
	dec := gob.NewDecoder(&buff)
	err := dec.Decode(&bloc)
	if err != nil {
		fmt.Println("block decoding error")
	}

	// verify block
	pubkey := datastruc.DecodePublic(bloc.PubKey)
	datatoverify := bloc.GetHash()
	if !bloc.Sig.Verify(datatoverify[:], pubkey) {
		fmt.Println("server", serv.id, "verifies a block, but the signature is wrong!")
		return
	}

	starttime := time.Now()
	if bloc.Blockhead.Kind == "txblock" {
		//res := serv.BlockTxValidateMultiThread(&bloc)
		res := serv.BlockTxValidateMultiThread(&bloc)
		//res := true
		if !res {
			fmt.Println("The received block contains unvalid mint-tx")
			return
		}
	} else if bloc.Blockhead.Kind == "configblock" {
		// todo, verify the signature for join-tx and leave-tx
		for _, jtx := range bloc.JoinTxList {
			if !jtx.Verify() {
				fmt.Println("The received block contains unvalid join-tx")
				return
			}
		}
		for _, ltx := range bloc.LeaveTxList {
			if !ltx.Verify() {
				fmt.Println("server", serv.id, "receives a block, but contains unvalid leave-tx, its content", ltx.Serialize(), "  its hash", ltx.TxHash, " its id ", ltx.Id, " its ip addr ", ltx.IpAddr, " its pubkey ", ltx.Pubkey, " its sig ", ltx.Sig)
				return
			}
		}
	} else {
		fmt.Println("The received block has wrong type")
		return
	}

	serv.msgbuff.Msgbuffmu.Lock()
	serv.msgbuff.BlockPool = append(serv.msgbuff.BlockPool, bloc)
	fmt.Println("server", serv.id, "receives a block at height", bloc.Blockhead.Height, "from instance", bloc.Blockhead.CreatorId, " with tx number", len(bloc.TransactionList))
	//fmt.Println("server", serv.id, "receives a block with", len(bloc.TransactionList), "txs in it")
	elapsed := time.Since(starttime).Milliseconds()
	serv.blockvalidatetime[bloc.Blockhead.Height] = int(elapsed)
	serv.msgbuff.Msgbuffmu.Unlock()

	fmt.Println("server", serv.id, "the block validation costs", elapsed, "ms")
}

func (serv *Server) handleConfirmedBlock(content []byte) {
	var buff bytes.Buffer
	var cbloc datastruc.ConfirmedBlock
	buff.Write(content)
	gob.Register(elliptic.P256())
	dec := gob.NewDecoder(&buff)
	err := dec.Decode(&cbloc)
	if err != nil {
		fmt.Println("confirmed block decoding error")
	}

	// todo, verify commit-qc
	// 1. the block hash and pre-prepare msg digest consistent
	// 2. the commit-qc has enough correct signature

	serv.msgbuff.Msgbuffmu.Lock()
	serv.msgbuff.ConfirmedBlockPool = append(serv.msgbuff.ConfirmedBlockPool, cbloc)

	fmt.Println("server", serv.id, "received a confirmed block")

	serv.msgbuff.Msgbuffmu.Unlock()
}

func (serv *Server) handleCheckpointMsg(content []byte) {
	var buff bytes.Buffer
	var ckpm datastruc.CheckPointMsg
	buff.Write(content)
	dec := gob.NewDecoder(&buff)
	err := dec.Decode(&ckpm)
	if err != nil {
		fmt.Println("checkpoint msg decoding error")
	}

	// add verification

	serv.msgbuff.Msgbuffmu.Lock()
	h := ckpm.Height
	serv.msgbuff.CheckpointVote[h] = append(serv.msgbuff.CheckpointVote[h], ckpm)
	serv.msgbuff.Msgbuffmu.Unlock()
}

func (serv *Server) handlePreprepareMsg(content []byte) {
	var buff bytes.Buffer
	var prepreparemsg datastruc.PrePrepareMsg
	buff.Write(content)
	dec := gob.NewDecoder(&buff)
	err := dec.Decode(&prepreparemsg)
	if err != nil {
		fmt.Println("pre-prepare msg decoding error")
	}
	// verify signature
	datatoverify := string(prepreparemsg.Ver) + "," + string(prepreparemsg.View) + "," + string(prepreparemsg.Order) + "," + string(prepreparemsg.Digest[:])
	pub := datastruc.DecodePublic(prepreparemsg.Pubkey)
	if !prepreparemsg.Sig.Verify([]byte(datatoverify), pub) {
		fmt.Println("server", serv.id, "receives an pre-prepare msg at height", prepreparemsg.Order, "but the signature is wrong")
		return
	}
	serv.msgbuff.Msgbuffmu.Lock()
	theprog := datastruc.Progres{prepreparemsg.Ver, prepreparemsg.View, prepreparemsg.Order}
	serv.msgbuff.Pre_preparelog[theprog] = prepreparemsg
	serv.msgbuff.Msgbuffmu.Unlock()
	fmt.Println("server", serv.id, "receives an pre-prepare msg at height", prepreparemsg.Order)
}

func (serv *Server) handlePrepareMsg(content []byte) {
	var buff bytes.Buffer
	var preparemsg datastruc.PrepareMsg
	buff.Write(content)
	dec := gob.NewDecoder(&buff)
	err := dec.Decode(&preparemsg)
	if err != nil {
		fmt.Println("prepare msg decoding error")
		log.Panic(err)
	}

	datatoverify := string(preparemsg.Ver) + "," + string(preparemsg.View) + "," + string(preparemsg.Order) + "," + string(preparemsg.Digest[:])
	pub := datastruc.DecodePublic(preparemsg.Pubkey)
	if !preparemsg.Sig.Verify([]byte(datatoverify), pub) {
		fmt.Println("server", serv.id, "receives an prepare msg at height", preparemsg.Order, "but the signature is wrong")
		return
	}

	serv.msgbuff.Msgbuffmu.Lock()
	theterm := datastruc.Term{preparemsg.Ver, preparemsg.View}
	theorder := preparemsg.Order
	if _, ok := serv.msgbuff.PrepareVote[theterm]; !ok {
		serv.msgbuff.PrepareVote[theterm] = make(map[int][]datastruc.PrepareMsg)
	}
	//serv.msgbuff.PrepareVote[theterm][theorder] = append(serv.msgbuff.PrepareVote[theterm][theorder], preparemsg)
	tmp := make([]datastruc.PrepareMsg, len(serv.msgbuff.PrepareVote[theterm][theorder]))
	copy(tmp, serv.msgbuff.PrepareVote[theterm][theorder])
	datastruc.AddPreparemsg(&tmp, preparemsg)
	delete(serv.msgbuff.PrepareVote[theterm], theorder)
	serv.msgbuff.PrepareVote[theterm][theorder] = make([]datastruc.PrepareMsg, len(tmp))
	copy(serv.msgbuff.PrepareVote[theterm][theorder], tmp)
	//fmt.Println("server", serv.id, "has ", len(serv.msgbuff.PrepareVote[theterm][theorder]), "prepare-vote at term", theterm, "height", preparemsg.Order)
	serv.msgbuff.Msgbuffmu.Unlock()
}

func (serv *Server) handleCommitMsg(content []byte) {
	var buff bytes.Buffer
	var commitmsg datastruc.CommitMsg
	buff.Write(content)
	dec := gob.NewDecoder(&buff)
	err := dec.Decode(&commitmsg)
	if err != nil {
		fmt.Println("commit msg decoding error")
	}
	datatoverify := string(commitmsg.Ver) + "," + string(commitmsg.View) + "," + string(commitmsg.Order) + "," + string(commitmsg.Digest[:])
	pub := datastruc.DecodePublic(commitmsg.Pubkey)
	if !commitmsg.Sig.Verify([]byte(datatoverify), pub) {
		fmt.Println("server", serv.id, "receives an commit msg at height", commitmsg.Order, "but the signature is wrong")
		return
	}
	serv.msgbuff.Msgbuffmu.Lock()
	theterm := datastruc.Term{commitmsg.Ver, commitmsg.View}
	theorder := commitmsg.Order
	if _, ok := serv.msgbuff.CommitVote[theterm]; !ok {
		serv.msgbuff.CommitVote[theterm] = make(map[int][]datastruc.CommitMsg)
	}
	//serv.msgbuff.CommitVote[theterm][theorder] = append(serv.msgbuff.CommitVote[theterm][theorder], commitmsg)
	tmp := make([]datastruc.CommitMsg, len(serv.msgbuff.CommitVote[theterm][theorder]))
	copy(tmp, serv.msgbuff.CommitVote[theterm][theorder])
	//tmpdigests := make([][]byte, 0)
	//for _, v := range tmp {
	//	tmpdigests = append(tmpdigests, v.Digest[0:6])
	//}
	//fmt.Println("server", serv.id, " tmp has ", len(tmp), "commit vote, tmpdigests ", tmpdigests)
	datastruc.AddCommitmsg(&tmp, commitmsg)
	delete(serv.msgbuff.CommitVote[theterm], theorder)
	serv.msgbuff.CommitVote[theterm][theorder] = make([]datastruc.CommitMsg, len(tmp))
	copy(serv.msgbuff.CommitVote[theterm][theorder], tmp)
	//digests := make([][]byte, 0)
	//for _, v := range serv.msgbuff.CommitVote[theterm][theorder] {
	//	digests = append(digests, v.Digest[0:6])
	//}
	//fmt.Println("server", serv.id, "has ", len(serv.msgbuff.CommitVote[theterm][theorder]), "commit-vote at term ", theterm," height", commitmsg.Order, "the digest is ", digests)
	serv.msgbuff.Msgbuffmu.Unlock()
}

func (serv *Server) handleViewChangeMsg(conten []byte) {
	var buff bytes.Buffer
	var vcmsg datastruc.ViewChangeMsg
	buff.Write(conten)

	dec := gob.NewDecoder(&buff)
	err := dec.Decode(&vcmsg)
	if err != nil {
		log.Panic(err)
	}

	datatoverify := []byte(string(vcmsg.Ver) + "," + string(vcmsg.View) + "," + string(vcmsg.SenderId) + "," + string(vcmsg.Lockheight))
	pub := datastruc.DecodePublic(vcmsg.Pubkey)
	if !vcmsg.Sig.Verify(datatoverify[:], pub) {
		fmt.Println("serve", serv.id, "receives a view-change msg, but the signature is wrong!")
		//fmt.Println("sender id is ", vcmsg.SenderId, " singed data is ", datatoverify, "\n")
		return
	}
	serv.msgbuff.Msgbuffmu.Lock()
	theterm := datastruc.Term{vcmsg.Ver, vcmsg.View}
	tmp := make([]datastruc.ViewChangeMsg, len(serv.msgbuff.Vcmsg[theterm]))
	copy(tmp, serv.msgbuff.Vcmsg[theterm])
	datastruc.AddVcmsg(&tmp, vcmsg)
	delete(serv.msgbuff.Vcmsg, theterm)
	serv.msgbuff.Vcmsg[theterm] = make([]datastruc.ViewChangeMsg, len(tmp))
	copy(serv.msgbuff.Vcmsg[theterm], tmp)
	//fmt.Println("serve", serv.id, "now has", len(serv.msgbuff.Vcmsg[theterm]), "view-change msg at ver", theterm.Ver, "view", theterm.View)
	serv.msgbuff.Msgbuffmu.Unlock()
}

func (serv *Server) handleNewViewMsg(conten []byte) {

	var buff bytes.Buffer
	var nvmsg datastruc.NewViewMsg
	buff.Write(conten)

	dec := gob.NewDecoder(&buff)
	err := dec.Decode(&nvmsg)
	if err != nil {
		log.Panic(err)
	}

	//nvvmsg := nvmsg
	//nvvmsg.Sig = datastruc.PariSign{}
	//nvvmsg.Pubkey = ""
	//datatoverify := sha256.Sum256(nvvmsg.Serialize())
	datatoverify := "newviewmsg," + string(nvmsg.Ver) + "," + string(nvmsg.View)
	pub := datastruc.DecodePublic(nvmsg.Pubkey)
	if !nvmsg.Sig.Verify([]byte(datatoverify), pub) {
		fmt.Println(fmt.Println("serve", serv.id, "receives a new-view msg, but the signature is wrong!"))
		return
	}

	if nvmsg.Kind == "p" {
		fmt.Println("server", serv.id, "received new-view msg in ver", nvmsg.Ver, "view", nvmsg.View, "with a prepare-lock at height", nvmsg.Lockheight)
	} else if nvmsg.Kind == "c" {
		fmt.Println("server", serv.id, "received new-view msg in ver", nvmsg.Ver, "view", nvmsg.View, "with a commit-lock at height", nvmsg.Lockheight)
	}

	theterm := datastruc.Term{nvmsg.Ver, nvmsg.View}
	serv.msgbuff.Msgbuffmu.Lock()
	serv.msgbuff.Newviewlog[theterm] = nvmsg
	if nvmsg.Bloc.Blockhead.Height > 0 {
		serv.msgbuff.BlockPool = append(serv.msgbuff.BlockPool, nvmsg.Bloc)
		thepreprepare := nvmsg.PPMsgSet[0]
		theprog := datastruc.Progres{thepreprepare.Ver, thepreprepare.View, thepreprepare.Order}
		serv.msgbuff.Pre_preparelog[theprog] = thepreprepare
	}
	serv.msgbuff.Msgbuffmu.Unlock()
}

func (serv *Server) handleMeasurementRes(content []byte) {
	var buff bytes.Buffer
	var meamresmsg datastruc.MeasurementResultMsg
	buff.Write(content)
	dec := gob.NewDecoder(&buff)
	err := dec.Decode(&meamresmsg)
	if err != nil {
		log.Panic(err)
	}

	serv.msgbuff.Msgbuffmu.Lock()
	hval := meamresmsg.GetHash()
	serv.msgbuff.MeasurementResPool[hval] = meamresmsg
	//fmt.Println("server", serv.id, "measurement result msg number is", len(serv.msgbuff.MeasurementResPool))
	serv.msgbuff.Msgbuffmu.Unlock()
}

func (serv *Server) handleSingleMeasurement(content []byte) {
	var buff bytes.Buffer
	var smmsg datastruc.SingleMeasurementAToB
	buff.Write(content)
	dec := gob.NewDecoder(&buff)
	err := dec.Decode(&smmsg)
	if err != nil {
		log.Panic(err)
	}

	serv.recvsinglemeasurementCh <- smmsg
}

func (serv *Server) handleStateTransferQuery(content []byte) {
	var buff bytes.Buffer
	var qstmsg datastruc.QueryStateTransMsg
	buff.Write(content)
	dec := gob.NewDecoder(&buff)
	err := dec.Decode(&qstmsg)
	if err != nil {
		log.Panic(err)
	}

	datatoverify := []byte("queryforstatetransfer" + string(qstmsg.Height))
	pub := datastruc.DecodePublic(qstmsg.Pubkey)
	if !qstmsg.Sig.Verify(datatoverify[:], pub) {
		fmt.Println("serv", serv.id, "received a query-for-state-transfer msg but the signature is wrong!")
	} else {
		fmt.Println("serv", serv.id, "received a query-for-state-transfer msg")
	}

	// tell pbft instance
	serv.statetransferqueryCh <- qstmsg
}

func (serv *Server) handleStateTransferReply(content []byte) {
	var buff bytes.Buffer
	var rstmsg datastruc.ReplyStateTransMsg
	buff.Write(content)
	dec := gob.NewDecoder(&buff)
	err := dec.Decode(&rstmsg)
	if err != nil {
		log.Panic(err)
	}

	datatoverify := []byte("replyforstatetransfer" + string(rstmsg.Height))
	pub := datastruc.DecodePublic(rstmsg.Pubkey)
	if !rstmsg.Sig.Verify(datatoverify[:], pub) {
		fmt.Println("serv", serv.id, "received a state-transfer-reply msg but the signature is wrong!")
	}

	// tell pbft instance
	serv.statetransferreplyCh <- rstmsg
}

func (serv *Server) handleProposeTest(conten []byte) {
	// todo, usually, the message should be decoded and verified before sending to pbft layer.
	datarecv := datastruc.DataReceived{"proposetest", conten}
	serv.cdetestrecvCh <- datarecv
}

func (serv *Server) handleWriteTest(conten []byte) {
	// todo, usually, the message should be decoded and verified before sending to pbft layer.
	datarecv := datastruc.DataReceived{"writetest", conten}
	serv.cdetestrecvCh <- datarecv
}

func (serv *Server) handleProposeResponseWoValidate(conten []byte) {
	//fmt.Println("server", serv.id, "receives a propose-response-wo")
	datarecv := datastruc.DataReceived{"proporesponwo", conten}
	serv.cderesponserecvCh <- datarecv
}

func (serv *Server) handleProposeResponseWithValidate(conten []byte) {
	//fmt.Println("server", serv.id, "receives a propose response with validation")
	datarecv := datastruc.DataReceived{"proporesponw", conten}
	serv.cderesponserecvCh <- datarecv
}

func (serv *Server) handleWriteResponseWoHash(conten []byte) {
	datarecv := datastruc.DataReceived{"writeresponwo", conten}
	serv.cderesponserecvCh <- datarecv
}

func (serv *Server) handleWriteResponseWithHash(conten []byte) {
	datarecv := datastruc.DataReceived{"writeresponw", conten}
	serv.cderesponserecvCh <- datarecv
}

func (serv *Server) handleWriteResponseWoHashFromOld(conten []byte) {
	datarecv := datastruc.DataReceived{"writeresponwofromold", conten}
	serv.cderesponserecvCh <- datarecv
}

func (serv *Server) handleWriteResponseWithHashFromOld(conten []byte) {
	datarecv := datastruc.DataReceived{"writeresponwfromold", conten}
	serv.cderesponserecvCh <- datarecv
}

func (serv *Server) handleProposeTestFromNew(conten []byte) {
	datarecv := datastruc.DataReceived{"proposetestfromnew", conten}
	serv.cdetestrecvCh <- datarecv
}

func (serv *Server) handleWriteResponseWoHashFromNew(conten []byte) {
	datarecv := datastruc.DataReceived{"writeresponwofromnew", conten}
	serv.cderesponserecvCh <- datarecv
}

func (serv *Server) handleWriteResponseWithHashFromNew(conten []byte) {
	datarecv := datastruc.DataReceived{"writeresponwfromnew", conten}
	serv.cderesponserecvCh <- datarecv
}

func (serv *Server) handleWriteTestFromNew(conten []byte) {
	datarecv := datastruc.DataReceived{"writetestfromnew", conten}
	fmt.Println("server", serv.id, "receives write-test-from-new")
	serv.cdetestrecvCh <- datarecv
}

func (serv *Server) handleProposeTestFromOld(conten []byte) {
	datarecv := datastruc.DataReceived{"proposetestfromold", conten}
	serv.cdetestrecvCh <- datarecv
}

func (serv *Server) handleWriteTestFromOld(conten []byte) {
	datarecv := datastruc.DataReceived{"writetestfromold", conten}
	serv.cdetestrecvCh <- datarecv
}

func (serv *Server) handleProposeResponseWoValidateFromOld(conten []byte) {
	datarecv := datastruc.DataReceived{"proporesponwofromold", conten}
	serv.cderesponserecvCh <- datarecv
}

func (serv *Server) handleProposeResponseWithValidateFromOld(conten []byte) {
	datarecv := datastruc.DataReceived{"proporesponwfromold", conten}
	serv.cderesponserecvCh <- datarecv
}

func (serv *Server) handleWriteResponseFromOld(conten []byte) {
	datarecv := datastruc.DataReceived{"writeresponfromold", conten}
	//fmt.Println("server", serv.id, "receives a write-response-to-new")
	serv.cderesponserecvCh <- datarecv
}

func (serv *Server) handleProposeResponseWoValidateFromNew(conten []byte) {
	datarecv := datastruc.DataReceived{"proporesponwofromnew", conten}
	serv.cderesponserecvCh <- datarecv
}

func (serv *Server) handleProposeResponseWithValidateFromNew(conten []byte) {
	datarecv := datastruc.DataReceived{"proporesponwfromnew", conten}
	serv.cderesponserecvCh <- datarecv
}

func (serv *Server) handleWriteResponseFromNew(conten []byte) {
	datarecv := datastruc.DataReceived{"writeresponfromnew", conten}
	serv.cderesponserecvCh <- datarecv
}

func (serv *Server) handleInformTest(conten []byte) {
	var buff bytes.Buffer
	var inftestmsg datastruc.RequestTestMsg
	buff.Write(conten)
	dec := gob.NewDecoder(&buff)
	err := dec.Decode(&inftestmsg)
	if err != nil {
		fmt.Println("inform request decoding error")
	}
	serv.RecvInformTestCh <- inftestmsg
}

func (serv *Server) BlockTxValidate(bloc *datastruc.Block) bool {
	validateres := true

	currbalance := make(map[string]int)
	serv.msgbuff.Msgbuffmu.Lock()
	for k, v := range serv.msgbuff.AccountBalance {
		currbalance[k] = v
	}
	serv.msgbuff.Msgbuffmu.Unlock()

	for _, tx := range bloc.TransactionList {
		if currbalance[tx.Source] >= tx.Value {
			if !tx.Verify(serv.clientacctopukstr[tx.Source]) {
				validateres = false
				fmt.Println("block contains some tx with unvalid signature")
				break
			}
			currbalance[tx.Source] -= tx.Value
			currbalance[tx.Recipient] += tx.Value
		} else {
			validateres = false
			fmt.Println("block contains some tx without enough balance")
			break
		}
	}
	return validateres
}

func (serv *Server) BlockTxValidateMultiThread(bloc *datastruc.Block) bool {
	ThreadNum := 2 // Thread number for tx validation
	if serv.id == 6 {
		ThreadNum = 4
	}
	results := make([]*bool, 0)
	for i := 0; i < ThreadNum; i++ {
		res := new(bool)
		*res = true
		results = append(results, res)
	}

	wg := new(sync.WaitGroup)
	wg.Add(ThreadNum)
	startpos := 0
	distance := len(bloc.TransactionList) / ThreadNum
	for i := 0; i < ThreadNum; i++ {
		txbatch := make([]datastruc.Transaction, 0)
		if i < ThreadNum-1 {
			txbatch = bloc.TransactionList[startpos:(startpos + distance)]
		} else {
			txbatch = bloc.TransactionList[startpos:len(bloc.TransactionList)]
		}
		go serv.TxBatchValidate(txbatch, wg, results[i])
		startpos = startpos + distance
	}
	wg.Wait()

	validateres := true
	for i := 0; i < ThreadNum; i++ {
		if !(*results[i]) {
			validateres = false
		}
	}

	return validateres
}

func (serv *Server) TxBatchValidate(txlist []datastruc.Transaction, wg *sync.WaitGroup, res *bool) {
	for _, tx := range txlist {
		if !tx.Verify(serv.clientacctopukstr[tx.Source]) {
			*res = false
			wg.Done()
		}
	}
	*res = true
	wg.Done()
}

func (serv *Server) ReadConfigFromRemote() []datastruc.PeerIdentity {

	// send "readconfig" request
	rcr := datastruc.NewReadConfigRequest(serv.id, serv.localallipsforserver[0])
	var buff bytes.Buffer
	enc := gob.NewEncoder(&buff)
	err := enc.Encode(rcr)
	if err != nil {
		log.Panic("readconfig request encode error")
	}
	content := buff.Bytes()
	destip := []string{"172.31.9.112:4000", "172.31.1.155:4010", "172.31.14.108:4020"}
	datatosend := datastruc.DatatosendWithIp{destip, "readconfig", content}
	serv.sendCh <- datatosend
	fmt.Println("server", serv.id, "send read config request to", destip, "waiting for reply, time", time.Since(serv.starttime).Seconds(), "s")

	// block, until receiving "replyconfigreply"
	reply := <-serv.recvconfigCh
	fmt.Println("server", serv.id, "receives read config reply signal from channel")
	return reply.Config
}

func (serv *Server) handleReadConfigRequest(content []byte) {
	// decode the request
	var buff bytes.Buffer
	var rcr datastruc.ReadConfigRequest
	buff.Write(content)
	dec := gob.NewDecoder(&buff)
	err := dec.Decode(&rcr)
	if err != nil {
		fmt.Println("ReadConfigRequest decoding error")
	}
	fmt.Println("server", serv.id, "the received read config request:", rcr)

	// send the reply back
	reply := datastruc.ReadConfigReply{serv.msgbuff.CurConfig}
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err = enc.Encode(reply)
	if err != nil {
		log.Panic("readconfig reply encode error")
	}
	conten := buf.Bytes()
	datatosend := datastruc.DatatosendWithIp{[]string{rcr.IpportAddr}, "readconfigreply", conten}
	serv.sendCh <- datatosend
	//fmt.Println("server", serv.id, "replies read config to", rcr.IpportAddr, " reply is ", reply)
}

func (serv *Server) handleReadConfigReply(conten []byte) {
	var reply datastruc.ReadConfigReply
	var buf bytes.Buffer
	buf.Write(conten)
	dec := gob.NewDecoder(&buf)
	err := dec.Decode(&reply)
	if err != nil {
		fmt.Println("config reply decoding error")
	}
	serv.recvconfigCh <- reply
	//fmt.Println("server", serv.id, "pushed read config reply signal into channel, the reply: ", reply)
}
