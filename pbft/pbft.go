package pbft

import (
	"../cachedb"
	"../datastruc"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/sha256"
	b64 "encoding/base32"
	"encoding/gob"
	"fmt"
	"log"
	"math"
	"sync"
	"time"
)

type persister struct {
	blockhashlist map[int][32]byte
	logterm map[int]datastruc.Term // height -> (ver, view)
	executedheight map[int]bool
	preparelock datastruc.PreparedLock
	commitlock datastruc.CommitedLock
	checkpointheight int
	accountbalance map[string]int
}

func (persis *persister) initialize() {
	persis.blockhashlist = make(map[int][32]byte)
	persis.logterm = make(map[int]datastruc.Term)
	persis.executedheight = make(map[int]bool)
	persis.accountbalance = make(map[string]int)
}

type PBFT struct {
	mu sync.Mutex

	Id int
	IpPortAddr string
	InitialTotalPeer int
	members []int
	membersexceptme []int


	PriKey *ecdsa.PrivateKey
	PubKey *ecdsa.PublicKey
	PriKeystr string
	PubKeystr string


	status int
	consenstatus int
	isleader bool
	leaderlease int
	reconfighappen bool
	curleaderlease int
	curleaderPubKeystr string

	senddatabyIpCh chan datastruc.DatatosendWithIp
	broadcdataCh chan datastruc.Datatosend
	memberidchangeCh chan datastruc.DataMemberChange
	prepreparedCh chan datastruc.Progres
	preparedCh chan datastruc.Progres
	committedCh chan datastruc.Progres
	vcmsgcollectedCh chan datastruc.Progres
	inauguratedCh chan datastruc.Progres
	configchangeCh chan int
	censorshipmonitorCh chan [32]byte
	censorshiphappenCh chan bool
	censorshipnothappenCh chan bool
	viewchangeduetocensorship [32]byte

	checkpointsignalCh chan int
	statetransferquerymonitorCh chan datastruc.QueryStateTransMsg
	statetransferreplyCh chan datastruc.ReplyStateTransMsg

	stopCh chan bool

	sentviewchangemsg map[datastruc.Term]bool
	sentnewviewmsg map[datastruc.Term]bool
	remainblocknuminnewview int
	preprepareMsgInNVMsg datastruc.PrePrepareMsg

	fmax int
	quorumsize int
	isbyzantine bool
	isjoining bool
	isleaving bool
	sentleavingtx bool

	vernumber 		int
	viewnumber 		int
	currentHeight 	int
	curblockhash [32]byte
	curblock *datastruc.Block

	curConfigure []datastruc.PeerIdentity
	succLine *datastruc.SuccLine
	persis *persister
	cachedb * cachedb.BlockChainCacheDB
	systemhash map[int][32]byte
	clientaccount map[int]string
	accountbalance map[string]int

	MsgBuff *datastruc.MessageBuffer

	acctx int
	starttime time.Time
	tpsstarttime time.Time
	singleconsensusstarttime time.Time
	consensustimelog map[int]int
	predictedconsensustimelog map[int]int
	leaderlog map[int]int
	singleviewchangestarttime time.Time
	viewchangetimelog []int
	singleinauguratestarttime time.Time
	inauguratetimelog []int

	tps []int
	leaverequeststarttime time.Time

	cdedata *datastruc.CDEdata
	cdeupdateflag bool
}

func CreatePBFTInstance(id int, ipaddr string, total int, clientpubkeystr map[int]string, msgbuf *datastruc.MessageBuffer,
	starttime time.Time, sendCh chan datastruc.DatatosendWithIp,
	broadCh chan datastruc.Datatosend, memberidchangeCh chan datastruc.DataMemberChange, censorshipmonitorCh chan [32]byte,
	statetransferqueryCh chan datastruc.QueryStateTransMsg, statetransferreplyCh chan datastruc.ReplyStateTransMsg,
	cdetestrecvch chan datastruc.DataReceived, cderesponserecvch chan datastruc.DataReceived,
	RecvInformTestCh chan datastruc.RequestTestMsg, recvsinglemeasurementCh chan datastruc.SingleMeasurementAToB,
	stopCh chan bool) *PBFT {
	pbft := &PBFT{}
	pbft.starttime = starttime
	pbft.Id = id
	pbft.IpPortAddr = ipaddr
	pbft.InitialTotalPeer = total
	pbft.UpdateQuorumSize(total)
	fmt.Println("instance", id, "thinks the quorum size should be", pbft.quorumsize)

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		log.Fatalln(err)
	}
	publicKey := &privateKey.PublicKey
	pbft.PriKey = privateKey
	pbft.PubKey = publicKey
	pbft.PriKeystr = datastruc.EncodePrivate(privateKey)
	pbft.PubKeystr = datastruc.EncodePublic(publicKey)

	pbft.members = make([]int, 0)
	pbft.membersexceptme = make([]int, 0)
	for i:=0; i<total; i++ {
		pbft.members = append(pbft.members, i)
		if i!=pbft.Id {
			pbft.membersexceptme = append(pbft.membersexceptme, i)
		}
	}

	pbft.cachedb = &cachedb.BlockChainCacheDB{}
	pbft.cachedb.Initialize(id)
	pbft.persis = &persister{}
	pbft.persis.initialize()
	pbft.MsgBuff = msgbuf
	pbft.senddatabyIpCh = sendCh
	pbft.broadcdataCh = broadCh
	pbft.memberidchangeCh = memberidchangeCh
	pbft.censorshipmonitorCh = censorshipmonitorCh
	pbft.statetransferquerymonitorCh = statetransferqueryCh
	pbft.statetransferreplyCh = statetransferreplyCh
	pbft.stopCh = stopCh
	pbft.status = stat_consensus
	pbft.consenstatus = Unstarted
	pbft.leaderlease = LeaderLease
	pbft.curleaderlease = LeaderLease


	pbft.initializeMapChan()
	pbft.initializeAccountBalance(clientpubkeystr)
	pbft.MsgBuff.UpdateBalance(pbft.accountbalance)
	//pbft.UpdateByzantineIdentity() //mechanism2 ,set byzantine leader
	if pbft.isbyzantine {
		fmt.Println("instance", pbft.Id, "is a byzantine guy")
	}


	//if pbft.Id==0 {
	//	pbft.isleaving = true
	//	fmt.Println("instance", pbft.Id, "will leave the system after a while")
	//} // mechanism2 set leaving node

	pbft.cdedata = datastruc.CreateCDEdata(pbft.Id, pbft.IpPortAddr, pbft.members, sendCh, broadCh, cdetestrecvch, cderesponserecvch, RecvInformTestCh, recvsinglemeasurementCh, pbft.PubKeystr, pbft.PriKey, clientpubkeystr)

	return pbft
}

func (pbft *PBFT) initializeMapChan() {

	pbft.prepreparedCh = make(chan datastruc.Progres)
	pbft.preparedCh = make(chan datastruc.Progres)
	pbft.committedCh = make(chan datastruc.Progres)
	pbft.vcmsgcollectedCh = make(chan datastruc.Progres)
	pbft.inauguratedCh = make(chan datastruc.Progres)
	pbft.configchangeCh = make(chan int)
	pbft.censorshiphappenCh = make(chan bool)
	pbft.censorshipnothappenCh = make(chan bool)
	pbft.checkpointsignalCh = make(chan int)
	pbft.systemhash = make(map[int][32]byte)

	pbft.sentviewchangemsg = make(map[datastruc.Term]bool)
	pbft.sentnewviewmsg = make(map[datastruc.Term]bool)
	pbft.clientaccount = make(map[int]string)
	pbft.accountbalance = make(map[string]int)

	pbft.consensustimelog = make(map[int]int)
	pbft.predictedconsensustimelog = make(map[int]int)
	pbft.leaderlog = make(map[int]int)
}

func (pbft *PBFT) initializeAccountBalance(clientpubkeystr map[int]string) {
	for k,v := range clientpubkeystr {
		hv := sha256.Sum256([]byte(v))
		acc := b64.StdEncoding.EncodeToString(hv[:])
		pbft.clientaccount[k] = acc
	}
	for _, v := range pbft.clientaccount {
		pbft.accountbalance[v] = 10
	}
	fmt.Println("instnace", pbft.Id, "maintains user account number:", len(pbft.accountbalance))
}

func (pbft *PBFT) InitialSetup() {

	fmt.Println("instance", pbft.Id, "initializes setup, total instance number in the system is", pbft.InitialTotalPeer)

	// peer discovery & build leader succession line
	go pbft.broadcastPubkey()
	theconfig := pbft.scanInitialConfig(pbft.InitialTotalPeer)
	pbft.curConfigure = []datastruc.PeerIdentity{}
	for i:=0; i<pbft.InitialTotalPeer; i++ {
		datastruc.ConstructConfigure(&pbft.curConfigure, theconfig[i])
	}
	pbft.succLine = datastruc.ConstructSuccessionLine(pbft.curConfigure)
	pbft.curleaderPubKeystr = pbft.succLine.CurLeader.Member.PubKey
	if pbft.curleaderPubKeystr==pbft.PubKeystr {
		pbft.isleader = true
		pbft.cdeupdateflag = true
	}

	// print leader succession line
	//fmt.Println("instace", pbft.Id, "thinks the leader succession line is")
	//pbft.succLine.SucclinePrint()
	//fmt.Println("instance", pbft.Id, "pubkey string is", pbft.PubKeystr)

	// construct genesis block
	confighash := pbft.succLine.GetHash()
	cdedatahash := pbft.cdedata.GenerateStateHash()
	pbft.systemhash[0] = datastruc.GenerateSystemHash(pbft.vernumber, pbft.currentHeight, confighash, [32]byte{}, cdedatahash)
	genesisb := datastruc.ConstructGenesisBlock(pbft.curConfigure)
	pbft.cachedb.UpdateFromGenesisb(genesisb)
	pbft.persis.blockhashlist[0] = genesisb.GetHash()
	pbft.persis.executedheight[0] = true
	pbft.MsgBuff.UpdateCurConfig(pbft.succLine.ConverToList())
	//fmt.Println("instance", pbft.Id, "updates msgbuff.curconfig:", pbft.succLine.ConverToList())


	pbft.status = stat_consensus
	pbft.status = stat_consensus
	pbft.currentHeight += 1
}

func (pbft *PBFT) LateSetup(peerlist []datastruc.PeerIdentity) {
	fmt.Println("instance", pbft.Id, "initializes late setup")

	//build current leader succession line and config
	pbft.curConfigure = peerlist
	pbft.succLine = datastruc.ConstructSuccessionLine(pbft.curConfigure)


	// test delay between itself and existing nodes the result is packed in join-tx
	le := len(pbft.cdedata.Peers)
	tmp := make([]int, le)
	copy(tmp, pbft.cdedata.Peers)
	pbft.cdedata.Peers = tmp[0:(le-1)] // new instance won't send test message to itself before joining the system
	start := time.Now()
	newjointx := pbft.cdedata.CollectDelayDataForNew(pbft.MsgBuff.ReadTxBatch(BlockVolume))
	elapsed := time.Since(start).Milliseconds()
	fmt.Println("new instance creates join-tx, costs", elapsed, "ms")
	pbft.cdedata.Peers = make([]int, le)
	copy(pbft.cdedata.Peers, tmp) // recover peers to include itself
	fmt.Println("new instance recovers peers: ", pbft.cdedata.Peers)

	// broadcast join-tx and wait for confirmed block
	pbft.broadcastJoinTx(newjointx)
	fmt.Println("node", pbft.Id, "is a new node, waits for the confirmed block")
	cblock := pbft.waitForConfirmedBlock()
	fmt.Println("node", pbft.Id, "is a new node, got the confirmed block")
	pbft.MsgBuff.UpdateJoinLeaveTxSetAfterCommitBlock(&cblock.Bloc)
	pbft.MsgBuff.UpdateConfirmedBlockPool(&cblock)
	pbft.cdedata.UpdateUsingPureDelayData(cblock.Cdedelaydata)
	fmt.Println("new-instance-cdedata.peers:", pbft.cdedata.Peers)
	// invoke state transfer and wait for state-transfer-reply
	pbft.QueryStateTransfer(cblock.Bloc.Blockhead.Height, 0) // todo, pick a dest or broadcast to the system
	thebalance := pbft.waitForStateTransferReply(cblock.Bloc.Blockhead.Height)
	//fmt.Println("node", pbft.Id, "is a new node, got the state transfer")

	// update persister and blockcachedb
	pbft.cachedb.UpdateAfterConfirmB(cblock)
	pbft.cachedb.UpdateAccountBalanceAtHeight(cblock.Bloc.Blockhead.Height-1, thebalance)


	pbft.persis.blockhashlist[cblock.Bloc.Blockhead.Height] = cblock.Bloc.GetHash()
	pbft.persis.logterm[cblock.Bloc.Blockhead.Height] = datastruc.Term{cblock.Bloc.Blockhead.Ver, cblock.CommiQC.CommitMsgSet[0].View}
	pbft.persis.executedheight[cblock.Bloc.Blockhead.Height] = true
	pbft.persis.checkpointheight = cblock.Bloc.Blockhead.Height
	pbft.persis.commitlock = datastruc.CommitedLock{cblock.Bloc.Blockhead.Height, cblock.PreppMsg, cblock.PreppMsg.Digest, cblock.CommiQC}
	for k,v := range thebalance {
		pbft.persis.accountbalance[k] = v
	}

	// generate a new succession line and config, includes itself
	pbft.curConfigure = cblock.Bloc.Configure
	//fmt.Println("new instance config:", cblock.Bloc.Configure)
	pbft.succLine = datastruc.ConstructSuccessionLine(cblock.Bloc.Configure)
	pbft.UpdateQuorumSize(pbft.succLine.Leng)
	fmt.Println("instance", pbft.Id, "thinks the current quorum size is", pbft.quorumsize)

	// generate system hash at current height
	for k,v := range thebalance {
		pbft.accountbalance[k] = v
	}
	pbft.currentHeight = cblock.Bloc.Blockhead.Height
	balancehash := pbft.generateaccountbalancehash(pbft.clientaccount, pbft.accountbalance)
	confighash := pbft.succLine.GetHash()
	cdedatahash := pbft.cdedata.GenerateStateHash()
	pbft.vernumber = cblock.Bloc.Blockhead.Ver
	pbft.viewnumber = cblock.CommiQC.CommitMsgSet[0].View
	fmt.Println("new instance ver:", pbft.vernumber, "currheight:", pbft.currentHeight)
	pbft.cdedata.PrintResult()
	pbft.systemhash[pbft.currentHeight] = datastruc.GenerateSystemHash(pbft.vernumber, pbft.currentHeight, confighash, balancehash, cdedatahash)

	// enter view-change stage
	// todo, need broadcast view-change msg, omit currently for simplicity.
	pbft.resetVariForViewChangeAfterReconfig()
	fmt.Println("the new instance late setup completes")
}

func (pbft *PBFT) Run() {
	tmp1 := time.Since(pbft.starttime).Seconds()
	fmt.Println("instance", pbft.Id, "starts running at", tmp1, "s")
	thetxs := pbft.MsgBuff.ReadTxBatch(BlockVolume)
	pbft.cdedata.FetchTxBatch(thetxs)
	fmt.Println("instance", pbft.Id, "cde data module fetches", len(thetxs), "txs")

	pbft.tpsstarttime = time.Now()
	go pbft.snapshot()
	go pbft.statetransfermonitor()
	go pbft.censorshipmonitor()
	go pbft.cdedata.CDEInformTestMonitor()
	closech := make(chan bool)
	go pbft.cdedata.CDETestMonitor(closech)
	go pbft.computeTps()

	pbft.MsgBuff.ClearTXPool()
	for {
		//elap := time.Since(pbft.starttime).Seconds()
		//if elap>74 {
		//	pbft.Stop()
		//}
		if pbft.currentHeight > 180 {
			pbft.Stop()
		}
		if pbft.isleaving && !pbft.sentleavingtx && pbft.currentHeight>=32 && false {
			// mechanism2, broadcast leaving request
			go pbft.broadcastLeavingTx()
			pbft.sentleavingtx = true
			pbft.leaverequeststarttime = time.Now()
			elaps := time.Since(pbft.starttime).Seconds()
			fmt.Println("instance", pbft.Id, "request to leave the system at", elaps, "s")
		}
		switch pbft.status {
		case stat_consensus:
			fmt.Println("instance ", pbft.Id," now enters consensus stage in ver ", pbft.vernumber, " view ",pbft.viewnumber,
				" in height ", pbft.currentHeight, "at time", time.Since(pbft.starttime).Seconds(), "s")
			pbft.singleconsensusstarttime =time.Now()
			if pbft.isleader && pbft.leaderlease>0 {
				if pbft.remainblocknuminnewview>0 {
					fmt.Println("node", pbft.Id, "is leader, dealing with pre-prepare msg in new-view msg in ver", pbft.vernumber, "view", pbft.viewnumber, "height", pbft.currentHeight)
					pbft.remainblocknuminnewview -= 1
					pbft.leaderlease -= 1
				} else {
					// update delay data before sending the first block
					if pbft.cdeupdateflag && pbft.cdedata.Round<=2 && pbft.currentHeight>=10 && pbft.currentHeight<=100 {
						// mechanism1
						// cdedata.Round initial value is 1
						// invoke a CDE dalay data update
						start:=time.Now()
						fmt.Println("instance", pbft.Id, "starts updating its delay data at round", pbft.cdedata.Round, "before driving consensus at height", pbft.currentHeight)
						thetxs := pbft.MsgBuff.ReadTxBatch(BlockVolume)
						delayv := pbft.cdedata.CreateDelayVector(thetxs)
						var mrmsg datastruc.MeasurementResultMsg
						closech := make(chan bool)
						pbft.cdedata.Recvmu.Lock()
						go pbft.cdedata.CDEResponseMonitor(closech)
						delayv.UpdateWrite()
						fmt.Println("update write and hash complete")
						delayv.UpdatePropose()
						fmt.Println("update propose and validate complete")
						mrmsg = datastruc.NewMeasurementResultMsg(pbft.cdedata.Id, pbft.cdedata.Round, pbft.cdedata.Peers,
							delayv.ProposeDelaydata, delayv.WriteDelaydata, delayv.ValidationDelaydata, delayv.HashDelaydata,
							pbft.cdedata.Pubkeystr,	pbft.cdedata.Prvkey)
						closech<-true
						pbft.cdedata.Recvmu.Unlock()

						// record the result to msgbuff, so that it will be packed in the forthcoming block, it does not need to be broadcasted to others
						pbft.MsgBuff.Msgbuffmu.Lock()
						hval := mrmsg.GetHash()
						pbft.MsgBuff.MeasurementResPool[hval] = mrmsg
						pbft.MsgBuff.Msgbuffmu.Unlock()

						elapsed := time.Since(start).Milliseconds()
						fmt.Println("instance", pbft.Id, "updating its delay data at round", pbft.cdedata.Round, "completes, time costs: ", elapsed, "ms" )
						pbft.cdedata.Round += 1
						pbft.cdeupdateflag = false
					}


					fmt.Println("leader ", pbft.Id," now starts driving consensus in ver ", pbft.vernumber, " view ",pbft.viewnumber," in height ", pbft.currentHeight, "\n")
					pbft.mu.Lock()
					var bloc datastruc.Block
					var blockhash [32]byte
					tmpres := pbft.MsgBuff.ConfigTxIsEmpty()
					if tmpres=="bothempty" {

						thetxpool := pbft.MsgBuff.ReadTxBatch(BlockVolume)
						fmt.Println("leader", pbft.Id, "has", len(pbft.MsgBuff.TxPool), "txs in its buffer, packing tx-block, reading tx number:", len(thetxpool))
						themeasurespool := pbft.MsgBuff.ReadMeasuremenResBatch()
						bloc = datastruc.NewTxBlock(pbft.Id, pbft.PubKeystr, pbft.PriKey, &thetxpool, themeasurespool, pbft.currentHeight, pbft.vernumber,
							pbft.persis.blockhashlist[pbft.currentHeight-1])
						blockhash = bloc.GetHash()
						go pbft.broadcastTxBlock(&bloc)
					} else if tmpres=="leavetxexists" {
						if !pbft.isbyzantine {
							theleavetx := pbft.MsgBuff.ReadLeaveTx()[0]
							peers := datastruc.GenerateNewConfigForLeave(pbft.succLine.ConverToList(), theleavetx)
							fmt.Println("leader", pbft.Id, "has leave-tx in its buffer, packing config-block for instance leaving at height",
								pbft.currentHeight, "the new config has", len(peers), "instances")
							bloc = datastruc.NewLeaveConfigBlock(pbft.PubKeystr, pbft.PriKey, theleavetx, peers, pbft.currentHeight, pbft.vernumber,
								pbft.persis.blockhashlist[pbft.currentHeight-1])
							blockhash = bloc.GetHash()
							go pbft.broadcastConfigBlock(&bloc)
						} else {
							fmt.Println("byzantine leader", pbft.Id, "censors the leave-tx at height", pbft.currentHeight)
							thetxpool := pbft.MsgBuff.ReadTxBatch(BlockVolume)
							themeasurespool := pbft.MsgBuff.ReadMeasuremenResBatch()
							bloc = datastruc.NewTxBlock(pbft.Id, pbft.PubKeystr, pbft.PriKey, &thetxpool, themeasurespool, pbft.currentHeight, pbft.vernumber,
								pbft.persis.blockhashlist[pbft.currentHeight-1])
							blockhash = bloc.GetHash()
							go pbft.broadcastTxBlock(&bloc)
							//time.Sleep(time.Millisecond * MonitorTimer)
						}
					} else if tmpres=="jointxexists" {
						thejointx := pbft.MsgBuff.ReadJoinTx()[0]
						fmt.Println("leader", pbft.Id, "has join-tx in its buffer, packing config-block for instance", thejointx.Id, "joining at height", pbft.currentHeight)
						peers := datastruc.GenerateNewConfigForJoin(pbft.succLine.ConverToList(), thejointx)
						bloc = datastruc.NewJoinConfigBlock(pbft.PubKeystr, pbft.PriKey, thejointx, peers, pbft.currentHeight, pbft.vernumber,
							pbft.persis.blockhashlist[pbft.currentHeight-1], pbft.systemhash[pbft.currentHeight-1])
						blockhash = bloc.GetHash()
						go pbft.broadcastConfigBlock(&bloc)
					} else {
						fmt.Println("leader buffer wrong!")
					}
					go pbft.broadcastPreprepare(pbft.vernumber, pbft.viewnumber, pbft.currentHeight, pbft.PriKey, blockhash)
					pbft.mu.Unlock()
					pbft.leaderlease -= 1

				}
			} else {
				pbft.leaderlease = LeaderLease
			}
			thetimer := time.NewTimer(time.Millisecond*ConsensusTimer)
			consensus_loop:
			for {
				if pbft.consenstatus==Unstarted {
					// todo, depends on if remainblocknuminnvmsg > 0
					var hval [32]byte
					pbft.mu.Lock()
					hval = pbft.systemhash[pbft.currentHeight-1]
					//fmt.Println("instance", pbft.Id, "scan pre-prepare msg with prev system hash: ", hval)
					go pbft.scanPreprepare(pbft.vernumber, pbft.viewnumber, pbft.currentHeight, pbft.curleaderPubKeystr, hval)
					//fmt.Println("instance", pbft.Id, "scan pre-prepare msg at height", pbft.currentHeight)
					pbft.mu.Unlock()
				}
				select {
				case <- pbft.censorshiphappenCh:
					fmt.Println("instance", pbft.Id, "thinks censorship attack for some leave-tx happens at height", pbft.currentHeight, "starts view change")
					pbft.mu.Lock()
					if pbft.sentviewchangemsg[datastruc.Term{pbft.vernumber, pbft.viewnumber+1}]==false{
						plock, clock := pbft.GenerateQCandLockForVC()
						go pbft.broadcastViewChange(pbft.vernumber, pbft.viewnumber+1, pbft.MsgBuff.ReadLeaveTx(), plock, clock, pbft.PubKeystr, pbft.PriKey)
						pbft.sentviewchangemsg[datastruc.Term{pbft.vernumber, pbft.viewnumber+1}]=true
					}
					pbft.resetVariForViewChange()
					pbft.mu.Unlock()
					break consensus_loop
				case <- thetimer.C:
					fmt.Println("instance", pbft.Id, "fails when consens height", pbft.currentHeight, "starts view change")
					pbft.mu.Lock()
					if pbft.sentviewchangemsg[datastruc.Term{pbft.vernumber, pbft.viewnumber+1}]==false{
						plock, clock := pbft.GenerateQCandLockForVC()
						go pbft.broadcastViewChange(pbft.vernumber, pbft.viewnumber+1, pbft.MsgBuff.ReadLeaveTx(), plock, clock, pbft.PubKeystr, pbft.PriKey)
						pbft.sentviewchangemsg[datastruc.Term{pbft.vernumber, pbft.viewnumber+1}]=true
					}
					pbft.resetVariForViewChange()
					pbft.mu.Unlock()
					break consensus_loop
				case prog :=<- pbft.prepreparedCh:

					// calculate the consensus delay after new node joining if there exists some join-tx
					if pbft.curblock.Blockhead.Kind=="configblock" {
						if len(pbft.curblock.JoinTxList) > 0 {
							jtx := pbft.curblock.JoinTxList[0]
							startt := time.Now()
							q := CalculateQuorumSize(len(pbft.members)+1)
							res1 := pbft.cdedata.CalculateConsensusDelayForNewJointx(pbft.Id, len(pbft.members)+1, q, jtx)
							res2 := pbft.cdedata.CalculateConsensusDelayForNewJointx(jtx.Id, len(pbft.members)+1, q, jtx)
							fmt.Println("consensus delay when instance", pbft.Id, "is leader: ", res1,
								"consensus delay when instance", jtx.Id, "is leader: ", res2)
							elaps := time.Since(startt).Milliseconds()
							res := EvaluateCapacity(res1, res2, pbft.Id, jtx.Id)
							if res {
								fmt.Println("The new instance may have enough capacity calculation costs: ", elaps, "ms")
							} else {
								fmt.Println("The new instance may not have enough capacity, waiting for view-change")
								time.Sleep(time.Millisecond * ConsensusTimer) // block here until view change,
								//todo, delete the join-tx, in case it is proposed again
							}
						}
					}
					pbft.mu.Lock()
					if prog.Ver==pbft.vernumber && prog.View==pbft.viewnumber && prog.Height==pbft.currentHeight && pbft.consenstatus==Unstarted {
						pbft.consenstatus = Preprepared
						fmt.Println("instance", pbft.Id, "is pre-prepared in ver",pbft.vernumber,"view", pbft.viewnumber, "height", pbft.currentHeight)
						go pbft.broadcastPrepare(pbft.vernumber, pbft.viewnumber, pbft.currentHeight, pbft.curblockhash)
						go pbft.scanPrepare(pbft.vernumber, pbft.viewnumber, pbft.currentHeight, pbft.curblockhash, pbft.quorumsize)
					}
					pbft.mu.Unlock()
				case prog :=<- pbft.preparedCh:
					pbft.mu.Lock()
					if prog.Ver==pbft.vernumber && prog.View==pbft.viewnumber && prog.Height==pbft.currentHeight && pbft.consenstatus==Preprepared {
						pbft.consenstatus = Prepared
						pbft.persis.preparelock.LockedHeight = pbft.currentHeight
						fmt.Println("instance", pbft.Id, "is prepared in ver",pbft.vernumber,"view", pbft.viewnumber, "height", pbft.currentHeight)
						//fmt.Println("instance ", pbft.Id, "broadcast commit msg with digest ", pbft.curblockhash)
						go pbft.broadcastCommit(pbft.vernumber, pbft.viewnumber, pbft.currentHeight, pbft.curblockhash)
						//fmt.Println("instance ", pbft.Id, "scan commit msg expect digest ", pbft.curblockhash)
						go pbft.scanCommit(pbft.vernumber, pbft.viewnumber, pbft.currentHeight, pbft.curblockhash, pbft.quorumsize)
					}
					pbft.mu.Unlock()
				case prog :=<- pbft.committedCh:
					pbft.mu.Lock()
					if prog.Ver==pbft.vernumber && prog.View==pbft.viewnumber && prog.Height==pbft.currentHeight && pbft.consenstatus==Prepared {
						pbft.consenstatus = Commited
						pbft.persis.commitlock.LockedHeight = pbft.currentHeight
						curheight := pbft.currentHeight
						pbft.CommitCurConsensOb()
						elapsed := time.Since(pbft.singleconsensusstarttime).Milliseconds()
						pbft.consensustimelog[curheight] = int(elapsed)
						pbft.leaderlog[curheight] = pbft.succLine.CurLeader.Member.Id
						pconsensusdelay := pbft.cdedata.CalculateConsensusDelay(pbft.succLine.CurLeader.Member.Id, pbft.succLine.Leng, pbft.quorumsize)[pbft.Id]
						pbft.predictedconsensustimelog[curheight] = pconsensusdelay // turnoff this when testing mechanism2

						pbft.curleaderlease -= 1
						fmt.Println("instance ", pbft.Id," now finishes height ", curheight, "time costs:", elapsed, "ms")
					}
					pbft.mu.Unlock()
					if pbft.reconfighappen {
						pbft.mu.Lock()
						pbft.currentHeight -= 1
						if pbft.sentviewchangemsg[datastruc.Term{pbft.vernumber+1, 0}]==false{
							plock, clock := pbft.GenerateQCandLockForVC()
							go pbft.broadcastViewChange(pbft.vernumber+1, 0, pbft.MsgBuff.ReadLeaveTx(), plock, clock, pbft.PubKeystr, pbft.PriKey)
							pbft.sentviewchangemsg[datastruc.Term{pbft.vernumber+1, 0}]=true
						}
						pbft.resetVariForViewChangeAfterReconfig()
						pbft.reconfighappen = false
						pbft.mu.Unlock()
					} else {
						if pbft.curleaderlease==0 {
							fmt.Println("instance",pbft.Id,"finds the current leader expires, launches a view change at height",pbft.currentHeight)
							pbft.mu.Lock()
							pbft.singleviewchangestarttime = time.Now()
							if pbft.sentviewchangemsg[datastruc.Term{pbft.vernumber, pbft.viewnumber+1}]==false{
								plock, clock := pbft.GenerateQCandLockForVC()
								go pbft.broadcastViewChange(pbft.vernumber, pbft.viewnumber+1, pbft.MsgBuff.ReadLeaveTx(), plock, clock, pbft.PubKeystr, pbft.PriKey)
								pbft.sentviewchangemsg[datastruc.Term{pbft.vernumber, pbft.viewnumber+1}]=true
							}
							pbft.resetVariForViewChange()
							pbft.mu.Unlock()
						}
					}
					break consensus_loop
				}
			}
		case stat_viewchange:
			fmt.Println("instance ", pbft.Id, " now enters view-change in ver ",pbft.vernumber," view ",pbft.viewnumber, " waiting for vcmsg!")
			pbft.mu.Lock()
			go pbft.scanViewChange(pbft.vernumber, pbft.viewnumber, pbft.quorumsize)
			pbft.mu.Unlock()
			select {
			case prog :=<- pbft.vcmsgcollectedCh:
				if prog.Ver==pbft.vernumber && prog.View==pbft.viewnumber {
					fmt.Println("instance", pbft.Id, "has collected enough view change msg in ver", prog.Ver,"view", prog.View)
					elaps := time.Since(pbft.singleviewchangestarttime).Milliseconds()
					pbft.viewchangetimelog = append(pbft.viewchangetimelog, int(elaps))
					pbft.status = stat_inaugurate
					pbft.singleinauguratestarttime = time.Now()
				}
			}
		case stat_inaugurate:
			fmt.Println("instance ", pbft.Id," now enters inauguration stage in ver ",pbft.vernumber, " view ", pbft.viewnumber, "\n")
			pbft.mu.Lock()
			theterm := datastruc.Term{pbft.vernumber, pbft.viewnumber}
			if pbft.isleader && pbft.sentnewviewmsg[theterm]==false {
				pbft.sentnewviewmsg[theterm] = true
				vcset := pbft.MsgBuff.ReadViewChangeQuorum(theterm, pbft.quorumsize)

				// decide the new-view msg type
				newviewkind, bloc := pbft.decideNewViewMsgKind(vcset)
				if pbft.isbyzantine && newviewkind=="withblock"{
					// mechanism2
					fmt.Println("byzantine leader deny sending new-view message!")
				} else {
					if newviewkind=="withoutblock" {
						go pbft.broadcastNewViewWithoutBlock(pbft.vernumber, pbft.viewnumber, vcset)
					} else if newviewkind=="withblock" {
						go pbft.broadcastNewViewWithBlock(pbft.vernumber, pbft.viewnumber, vcset, bloc)
					}
				}

			}
			thever := pbft.vernumber
			theview := pbft.viewnumber
			pbft.mu.Unlock()
			go pbft.scanNewView(thever, theview, pbft.curleaderPubKeystr)
			thetimer := time.NewTimer(time.Millisecond*InauguratTimer)
			inaugurate_loop:
			for {
				select {
				case <-thetimer.C:
					fmt.Println("instance", pbft.Id, "view-change timer expires when waiting for the new leader's inauguration in ver",pbft.vernumber, "view",pbft.viewnumber, "height", pbft.currentHeight)
					pbft.mu.Lock()
					if pbft.sentviewchangemsg[datastruc.Term{pbft.vernumber, pbft.viewnumber+1}]==false{
						plock, clock := pbft.GenerateQCandLockForVC()
						go pbft.broadcastViewChange(pbft.vernumber, pbft.viewnumber+1, pbft.MsgBuff.ReadLeaveTx(), plock, clock, pbft.PubKeystr, pbft.PriKey)
						pbft.sentviewchangemsg[datastruc.Term{pbft.vernumber, pbft.viewnumber+1}]=true
						fmt.Println("instance", pbft.Id, "broadcasts view-change msg in view", pbft.viewnumber,
							"prepare-locked height:", pbft.persis.preparelock.LockedHeight, "commit-locked height:",
							pbft.persis.commitlock.LockedHeight)
					}
					pbft.resetVariForViewChange()
					pbft.mu.Unlock()
					break inaugurate_loop
				case theprog:=<- pbft.inauguratedCh:
					if theprog.Ver==pbft.vernumber && theprog.View==pbft.viewnumber {
						pbft.mu.Lock()
						pbft.consenstatus = Unstarted
						pbft.status = stat_consensus
						if !datastruc.HashEqualDefault(pbft.viewchangeduetocensorship) {
							fmt.Println("instance", pbft.Id, "has censored leave-tx, monitor it!")
							pbft.censorshipmonitorCh <- pbft.viewchangeduetocensorship
							pbft.viewchangeduetocensorship = [32]byte{}
						}
						pbft.currentHeight = theprog.Height
						pbft.curleaderlease = LeaderLease
						fmt.Println("instance",pbft.Id, "got new-view signal in ver", theprog.Ver, "view", theprog.View)

						elaps := time.Since(pbft.singleinauguratestarttime).Milliseconds()
						pbft.inauguratetimelog = append(pbft.inauguratetimelog, int(elaps))
						pbft.mu.Unlock()
						break inaugurate_loop
					}
				}
			}
		}
	}
}

func (pbft *PBFT) censorshipmonitor() {
	for {
		select {
		case thehash :=<- pbft.censorshipmonitorCh:
			fmt.Println("instance", pbft.Id, "starts timer to monitor the leave-tx")
			thetimer := time.NewTimer(time.Millisecond * MonitorTimer)
			select {
			case <-thetimer.C:
				fmt.Println("instance", pbft.Id, "the monitored leave-tx fail to consens, trigger view-change")
				pbft.viewchangeduetocensorship = thehash
				pbft.censorshiphappenCh<-true
			case <-pbft.censorshipnothappenCh:
				fmt.Println("instance", pbft.Id, "finds the monitored leave-tx consensed, timer stops")
			}
		}
	}
}


func (pbft *PBFT) snapshot() {

	for {
		select {
		case ckph :=<- pbft.checkpointsignalCh:
			// keep all state data, in case that consensus is too fast and change them
			starttime := time.Now()
			pbft.mu.Lock()
			ver := pbft.vernumber
			clientacc := make(map[int]string)
			for k,v:=range pbft.clientaccount {
				clientacc[k] = v
			}
			accbalance := make(map[string]int)
			for k,v:=range pbft.accountbalance {
				accbalance[k] = v
			}
			quorumsize := pbft.quorumsize
			pbft.mu.Unlock()
			elasp := time.Since(starttime).Milliseconds()
			fmt.Println("copy state data costs", elasp, "ms")

			// generate system hash
			balancehash := pbft.generateaccountbalancehash(clientacc, accbalance)
			confighash := pbft.succLine.GetHash() // todo, may be problematic
			cdedatahash := pbft.cdedata.GenerateStateHash()
			thehash := datastruc.GenerateSystemHash(ver, ckph, confighash, balancehash, cdedatahash)
			pbft.systemhash[pbft.currentHeight] = thehash
			// broadcast syshash
			checkpmsg := datastruc.NewCheckPointMsg(pbft.Id, ckph, thehash, pbft.PubKeystr)
			go pbft.broadcastCheckPoint(checkpmsg)

			// wait for Q vote
			res := pbft.scanCheckPoint(ckph, thehash,quorumsize) //block here
			if res {
				fmt.Println("stable checkpoint generated at height", ckph, "system hash: ", thehash)
				pbft.persis.checkpointheight = ckph
				pbft.persis.accountbalance = pbft.accountbalance
				// todo checkpoint qc
			} else {
				fmt.Println("can't collect enough checkpoint message at height", ckph, "exit")
			}
		}
	}
}

func (pbft *PBFT) scanCheckPoint(h int, syshash [32]byte, q int) bool {
	timeouter := time.NewTimer(time.Second*ThreadExit)
	for {
		select {
		case <- timeouter.C:
			return false
		default:
			// todo scancheckpoint
			acc := pbft.MsgBuff.CountCheckpointVote(h, syshash)
			if acc>=q {
				return true
			} else {
				time.Sleep(time.Millisecond*ScanInterval)
			}
		}
	}
}


func (pbft *PBFT) statetransfermonitor() {
	for {
		select {
		case stfqmsg :=<- pbft.statetransferquerymonitorCh:
			fmt.Println("instance", pbft.Id, "receives a state-transfer-query at height", stfqmsg.Height)
			pbft.ReplyStateTransfer(stfqmsg.Height, stfqmsg.Id)
		}
	}
}

func (pbft *PBFT) UpdateByzantineIdentity() {
	if pbft.Id==3 || pbft.Id==4 {
		pbft.isbyzantine = true
	}
}

func (pbft *PBFT) UpdateQuorumSize(n int) {
	x := float64(n-1)
	y := 3.0
	f := int(math.Floor(x/y))
	pbft.fmax = f
	z := float64((n + f + 1))/2.0
	q := int(math.Ceil(z))
	pbft.quorumsize = q
	//fmt.Println("instance", pbft.Id, "updates quorum size, the total number is", n, "quorum size is", q)
}

func CalculateQuorumSize(n int) int {
	x := float64(n-1)
	y := 3.0
	f := int(math.Floor(x/y))
	z := float64((n + f + 1))/2.0
	q := int(math.Ceil(z))
	return q
}

func (pbft *PBFT) updateaccountbalance() {

	for _, tx := range pbft.curblock.TransactionList {
		pbft.accountbalance[tx.Source] -= tx.Value
		pbft.accountbalance[tx.Recipient] += tx.Value
	}
}

func (pbft *PBFT) scanInitialConfig(total int) []datastruc.PeerIdentity {
	for {
		ok, theconfig := pbft.MsgBuff.ReadInitialConfig(total)
		if ok {
			return theconfig
		}
		time.Sleep(time.Millisecond * ScanInterval)
	}
}

func (pbft *PBFT) scanConfirmedBlock() datastruc.ConfirmedBlock {
	for {
		ok, cbloc := pbft.MsgBuff.ReadConfirmedBlock()
		if ok {
			return cbloc
		}
		time.Sleep(time.Millisecond * ScanInterval)
	}
}

func (pbft *PBFT) scanPreprepare(ver, view, heigh int, leaderpubkey string, syshash [32]byte) {
	timeouter := time.NewTimer(time.Second*ThreadExit)
	theprog := datastruc.Progres{ver, view, heigh}
	for {
		select {
		case <- timeouter.C:
			return
		default:
			thepreprepare, ok := pbft.MsgBuff.ReadPrepreparelog(theprog)
			if ok {
				pbft.mu.Lock()
				if pbft.persis.commitlock.LockedHeight >= heigh && view == thepreprepare.View {
					// means the current height is a re-proposal for an already commited height
					// TODO, change to pbft.persis.commitlock.LockedHeight>=heigh
					pbft.curblockhash = thepreprepare.Digest
					pbft.curblock = &pbft.cachedb.ReadBlockFromDB(heigh, heigh)[0]
					pbft.mu.Unlock()
					pbft.prepreparedCh <- theprog
					return
				} else {
					if view == thepreprepare.View && thepreprepare.Pubkey == leaderpubkey {
						searchres, theblock := pbft.MsgBuff.SearchBlock(thepreprepare.Digest)
						if searchres {
							pbft.curblockhash = thepreprepare.Digest
							pbft.curblock = theblock
							pbft.mu.Unlock()
							pbft.prepreparedCh <- theprog
							return
						}
					}
				}
				pbft.mu.Unlock()
			}
			time.Sleep(time.Millisecond*ScanInterval)
		}
	}
}

func (pbft *PBFT) scanPrepare(ver, view, heigh int, digest [32]byte, quorumsize int) {

	timeouter := time.NewTimer(time.Second*ThreadExit)
	theterm := datastruc.Term{ver, view}
	for {
		select {
		case <- timeouter.C:
			return
		default:
			acc := pbft.MsgBuff.CountPrepareVote(theterm, heigh, digest)
			//fmt.Println("instance", pbft.Id, "got", acc, "prepare-vote at height", heigh)
			if acc>=quorumsize {
				//fmt.Println("instance", pbft.Id, "finds", acc,"prepare-vote in height", heigh)
				theprog := datastruc.Progres{ver, view, heigh}
				pbft.mu.Lock()
				thepreprepare, _ := pbft.MsgBuff.ReadPrepreparelog(theprog)
				pbft.persis.preparelock = datastruc.PreparedLock{heigh, thepreprepare, thepreprepare.Digest,
					datastruc.PrepareQC{pbft.MsgBuff.ReadPrepareVoteQuorum(theterm, heigh, quorumsize)}}
				pbft.mu.Unlock()
				//fmt.Println("instance", pbft.Id, "got", acc, "prepare-vote at height", heigh)
				pbft.cachedb.UpdateAfterPrepare(heigh, digest, pbft.persis.preparelock.LockedQC)
				pbft.preparedCh<-theprog
				return
			} else {
				time.Sleep(time.Millisecond*ScanInterval)
			}
		}
	}
}

func (pbft *PBFT) scanCommit(ver, view, heigh int, digest [32]byte, quorumsize int) {
	timeouter := time.NewTimer(time.Second*ThreadExit)
	theterm := datastruc.Term{ver, view}
	for {
		select {
		case <- timeouter.C:
			return
		default:
			//fmt.Println("instance ", pbft.Id, "counts commit vote, the input is term: ", theterm, " height ", heigh)
			acc := pbft.MsgBuff.CountCommitVote(theterm, heigh, digest)
			//fmt.Println("instance", pbft.Id, "got", acc, "commit-vote at height", heigh)
			if acc>=quorumsize {
				theprog := datastruc.Progres{ver, view, heigh}
				pbft.mu.Lock()
				thepreprepare, ok := pbft.MsgBuff.ReadPrepreparelog(theprog)
				if ok {
					pbft.persis.commitlock = datastruc.CommitedLock{heigh, thepreprepare,
						thepreprepare.Digest,datastruc.CommitQC{pbft.MsgBuff.ReadCommitVoteQuorum(theterm, heigh, quorumsize)}}
					pbft.mu.Unlock()
					//fmt.Println("instance", pbft.Id, "got", acc, "commit-vote at height", heigh)
					pbft.committedCh<-theprog
					return
				}
			} else {
				time.Sleep(time.Millisecond*ScanInterval*10)
			}
		}
	}
}

func (pbft *PBFT) scanViewChange(ver, view, quorumsize int) {
	fmt.Println("instance", pbft.Id, "scans view-change msg in ver", ver, "view", view)
	timeouter := time.NewTimer(time.Second*ThreadExit)
	theterm := datastruc.Term{ver, view}
	for {
		select {
		case <- timeouter.C:
			return
		default:
			le := pbft.MsgBuff.CountViewChangeVote(theterm)
			if le>=quorumsize {
				//fmt.Println("instance", pbft.Id, "got", le, "view-change msg in ver", ver, "view", view)
				pbft.vcmsgcollectedCh<-datastruc.Progres{ver, view, 0}
				return
			} else {
				time.Sleep(time.Millisecond*ScanInterval)
			}
		}
	}
}

func (pbft *PBFT) scanNewView(ver, view int, leaderpubkey string) {
	timeouter := time.NewTimer(time.Millisecond*InauguratTimer)
	theterm := datastruc.Term{ver, view}
	for {
		select {
		case <- timeouter.C:
			return
		default:
			nvmsg, ok := pbft.MsgBuff.ReadNewViewlog(theterm)
			pbft.mu.Lock()
			if ok {
				if nvmsg.Pubkey==leaderpubkey {
					if nvmsg.Kind=="c" && pbft.persis.commitlock.LockedHeight==nvmsg.Lockheight {
						if nvmsg.Bloc.Blockhead.Height==0 {
							// means there is no config-block in new-view msg
							fmt.Println("instance ",pbft.Id," local committed height equals the new-view msg commit-locked height, enters the next height, the leade will freely propose")
							pbft.remainblocknuminnewview = 0
							pbft.mu.Unlock()
							pbft.inauguratedCh <- datastruc.Progres{ver, view, pbft.persis.commitlock.LockedHeight + 1}
							return
						} else {
							pbft.remainblocknuminnewview = 1
							pppmsg := nvmsg.PPMsgSet[0]
							theprog := datastruc.Progres{pppmsg.Ver, pppmsg.View, pppmsg.Order}
							pbft.mu.Unlock()
							fmt.Println("instance ",pbft.Id," finds a config-block in new-view msg, enters the next height", pppmsg.Order, "to deal with it")
							pbft.inauguratedCh <- theprog
							return
						}
					} else {
						log.Panic("corner case happens")
					}
				}
			}
			pbft.mu.Unlock()
			time.Sleep(time.Millisecond*ScanInterval)
		}
	}
}

func (pbft *PBFT) generateaccountbalancehash(clientaccount map[int]string, accountbalance map[string]int) [32]byte {

	value := make([]int, 0)
	for i:=0; i<len(clientaccount); i++ {
		value = append(value, accountbalance[clientaccount[i]])
	}

	var content []byte
	for _,v:=range value {
		datastruc.EncodeInt(&content, v)
	}

	hashv := sha256.Sum256(content)
	return hashv
}

func (pbft *PBFT) GenerateQCandLockForVC() (datastruc.PreparedLock, datastruc.CommitedLock) {
	//ckpqc := datastruc.CheckPointQC{}
	plock := datastruc.PreparedLock{}
	clock := datastruc.CommitedLock{}

	if pbft.persis.preparelock.LockedHeight>pbft.persis.commitlock.LockedHeight {
		// case1 has a prepared but uncommited block
		//blochead := pbft.cachedb.ReadBlockHeadFromDB(pbft.persis.commitlock.LockedHeight)
		//ckpointqc := pbft.persis.preparelock.LockedQC
		//ckpqc = datastruc.CheckPointQC{blochead, ckpointqc}
		plock = pbft.persis.preparelock
		// clock is empty
		//fmt.Println("instance", pbft.Id, "generates a valid prepare-lock and an empty commit-lock at height", plock.LockedHeight)
	} else {
		// case2 doesn't have a parpared block
		// read the stable checkpoint block from database
		//blochead := pbft.cachedb.ReadBlockHeadFromDB(pbft.persis.commitlock.LockedHeight)
		//ckpointqc := pbft.cachedb.ReadPrepareQCFromDB(pbft.persis.commitlock.LockedHeight, pbft.persis.commitlock.LockedHeight)[0]
		//ckpqc = datastruc.CheckPointQC{blochead, ckpointqc}
		// plock is empty
		clock = pbft.persis.commitlock
		//fmt.Println("instance", pbft.Id, "generates a valid commit-lock and an empty prepare-lock at height", clock.LockedHeight)
	}
	return plock, clock
}

func (pbft *PBFT) resetVariForViewChange() {
	pbft.status = stat_viewchange
	pbft.viewnumber += 1
	// consensus status change?
	pbft.succLine.RotateLeader()
	pbft.curleaderPubKeystr = pbft.succLine.CurLeader.Member.PubKey
	if pbft.PubKeystr == pbft.curleaderPubKeystr {
		pbft.isleader = true
	} else {
		pbft.isleader = false
	}
	pbft.curblockhash = [32]byte{}
	pbft.curblock = &datastruc.Block{}
	pbft.cdeupdateflag = true
}

func (pbft *PBFT) resetVariForViewChangeAfterReconfig() {
	pbft.status = stat_viewchange
	pbft.vernumber += 1
	pbft.viewnumber = 0
	pbft.currentHeight += 1
	pbft.curleaderPubKeystr = pbft.succLine.CurLeader.Member.PubKey
	if pbft.PubKeystr == pbft.curleaderPubKeystr {
		pbft.isleader = true
	} else {
		pbft.isleader = false
	}
	pbft.curblockhash = [32]byte{}
	pbft.curblock = &datastruc.Block{}
	pbft.cdeupdateflag = true
}

func (pbft *PBFT) VirtuallyCommitConsensOb() [32]byte {
	var syshash [32]byte

	return syshash
}

func (pbft *PBFT) CommitCurConsensOb() {

	if pbft.curblock.Blockhead.Kind=="txblock" {
		if pbft.persis.executedheight[pbft.currentHeight] == false {
			pbft.acctx += len(pbft.curblock.TransactionList)
			pbft.updateaccountbalance()
			pbft.MsgBuff.UpdateBalance(pbft.accountbalance)

			pbft.MsgBuff.UpdateTxPoolAfterCommitBlock(pbft.curblock)
			pbft.MsgBuff.UpdateMeasurementResAfterCommitBlock(pbft.curblock)
			pbft.MsgBuff.UpdateBlockPoolAfterCommitBlock(pbft.curblock)
			pbft.cdedata.UpdateUsingNewMeasurementRes(pbft.curblock.MeasurementResList)

			//if pbft.currentHeight%15==0 {
			//	fmt.Println("cde data result at", time.Since(pbft.starttime).Seconds(), "s:")
			//	pbft.cdedata.PrintResult()
			//} // mechanism1


			theterm := datastruc.Term{pbft.vernumber, pbft.viewnumber}
			commqc := datastruc.CommitQC{pbft.MsgBuff.ReadCommitVoteQuorum(theterm, pbft.currentHeight, pbft.quorumsize)}
			pbft.cachedb.UpdateAfterCommit(pbft.currentHeight, pbft.curblock, pbft.accountbalance, commqc)
			pbft.persis.blockhashlist[pbft.currentHeight] = pbft.curblockhash
			pbft.persis.logterm[pbft.currentHeight] = datastruc.Term{pbft.vernumber, pbft.viewnumber}
			pbft.persis.executedheight[pbft.currentHeight] = true

			if pbft.currentHeight%CheckPointInterv==0 {
				pbft.checkpointsignalCh <- pbft.currentHeight
			}

			pbft.consenstatus = Unstarted
			pbft.currentHeight += 1
			pbft.curblockhash = [32]byte{}
		} else {
			log.Panic("the height has been executed")
		}
	} else if pbft.curblock.Blockhead.Kind=="configblock" {
		if pbft.persis.executedheight[pbft.currentHeight]==false {
			fmt.Println("instance", pbft.Id, "executes a config-block at height", pbft.currentHeight)

			if len(pbft.curblock.LeaveTxList)>0 {
				// leaving instance stops, other instances tell the up layer server to delete that ip
				// inform server to stop sending messages to the leaving node
				pbft.MsgBuff.UpdateBlockPoolAfterCommitBlock(pbft.curblock)
				pbft.MsgBuff.UpdateJoinLeaveTxSetAfterCommitBlock(pbft.curblock)
				theterm := datastruc.Term{pbft.vernumber, pbft.viewnumber}
				commqc := datastruc.CommitQC{pbft.MsgBuff.ReadCommitVoteQuorum(theterm, pbft.currentHeight, pbft.quorumsize)}
				pbft.cachedb.UpdateAfterCommit(pbft.currentHeight, pbft.curblock, pbft.accountbalance, commqc)

				theleavingid := pbft.curblock.LeaveTxList[0].Id
				datatosend := datastruc.DataMemberChange{"leave", theleavingid, ""}
				pbft.memberidchangeCh <- datatosend
				pbft.censorshipnothappenCh <- true
				if pbft.Id==theleavingid {
					requestprocessingtime := time.Since(pbft.leaverequeststarttime).Milliseconds()
					fmt.Println("instance", pbft.Id, " the leaving-tx processing time is", requestprocessingtime, "ms")
					fmt.Println("the leaving-tx processing time(ms) is", requestprocessingtime)
					pbft.Stop()
				} else {
					// update member and memberexceptme
					tmp1 := make([]int, 0)
					tmp2 := make([]int, 0)
					for _,v := range pbft.members {
						if v!=theleavingid {
							tmp1 = append(tmp1, v)
							if v!=pbft.Id {
								tmp2 = append(tmp2, v)
							}
						}
					}
					pbft.members = make([]int, len(tmp1))
					pbft.membersexceptme = make([]int, len(tmp2))
					copy(pbft.members, tmp1)
					copy(pbft.membersexceptme, tmp2)
					fmt.Println("instance", pbft.Id,"updates members to", pbft.members, "membersexceptme to", pbft.membersexceptme)

				}


				pbft.succLine = datastruc.ConstructSuccessionLine(pbft.curblock.Configure)
				pbft.succLine.CurLeader = pbft.succLine.Tail.Next
				pbft.MsgBuff.UpdateCurConfig(pbft.succLine.ConverToList())
				pbft.UpdateQuorumSize(pbft.succLine.Leng)

				pbft.persis.blockhashlist[pbft.currentHeight] = pbft.curblockhash
				pbft.persis.logterm[pbft.currentHeight] = datastruc.Term{pbft.vernumber, pbft.viewnumber}
				pbft.persis.executedheight[pbft.currentHeight] = true

				if pbft.currentHeight%CheckPointInterv==0 {
					pbft.checkpointsignalCh <- pbft.currentHeight
				}
				pbft.reconfighappen = true
				pbft.currentHeight += 1
			} else if len(pbft.curblock.JoinTxList)>0 {
				pbft.MsgBuff.UpdateBlockPoolAfterCommitBlock(pbft.curblock)
				pbft.MsgBuff.UpdateJoinLeaveTxSetAfterCommitBlock(pbft.curblock)
				fmt.Println("instance", pbft.Id, "cdedata before adding new node:")
				pbft.cdedata.PrintResult()
				pbft.cdedata.AddNewInstanceData(pbft.curblock.JoinTxList[0])
				fmt.Println("instance", pbft.Id, "cdedata after adding new node:")
				pbft.cdedata.PrintResult()
				//fmt.Println(pbft.Id, "instance-cdedata.peers:", pbft.cdedata.Peers)

				theterm := datastruc.Term{pbft.vernumber, pbft.viewnumber}
				commqc := datastruc.CommitQC{pbft.MsgBuff.ReadCommitVoteQuorum(theterm, pbft.currentHeight, pbft.quorumsize)}
				pbft.cachedb.UpdateAfterCommit(pbft.currentHeight, pbft.curblock, pbft.accountbalance, commqc)

				thejoinid := pbft.curblock.JoinTxList[0].Id
				thejoinaddr := pbft.curblock.JoinTxList[0].IpAddr
				datatosend := datastruc.DataMemberChange{"join", thejoinid, thejoinaddr}
				fmt.Println("instance", pbft.Id,"tells communication layer to add an addr:", thejoinaddr)
				pbft.memberidchangeCh <- datatosend
				pbft.members = append(pbft.members, thejoinid)
				pbft.membersexceptme = append(pbft.membersexceptme, thejoinid)

				pbft.succLine = datastruc.ConstructSuccessionLine(pbft.curblock.Configure)
				pbft.succLine.CurLeader = pbft.succLine.Tail.Next
				pbft.MsgBuff.UpdateCurConfig(pbft.succLine.ConverToList())
				pbft.UpdateQuorumSize(pbft.succLine.Leng)
				fmt.Println("instance", pbft.Id, "thinks the current quorum size is", pbft.quorumsize)

				//if pbft.Id==0 {
				//	pbft.cdedata.PrintResult()
				//}

				pbft.persis.blockhashlist[pbft.currentHeight] = pbft.curblockhash
				pbft.persis.logterm[pbft.currentHeight] = datastruc.Term{pbft.vernumber, pbft.viewnumber}
				pbft.persis.executedheight[pbft.currentHeight] = true
				if pbft.currentHeight%CheckPointInterv==0 {
					pbft.checkpointsignalCh <- pbft.currentHeight
				}
				pbft.reconfighappen = true
				pbft.currentHeight += 1

				time.Sleep(time.Millisecond * 10)
				if pbft.isleader {
					theprog := datastruc.Progres{pbft.vernumber, pbft.viewnumber, pbft.currentHeight}
					pppmsg, _ := pbft.MsgBuff.ReadPrepreparelog(theprog)
					cdep := pbft.cdedata.GeneratePureDelayData()
					cblock := datastruc.ConfirmedBlock{pppmsg, *pbft.curblock,commqc, cdep}
					pbft.InformNewPeer(cblock, thejoinid)
					elapsed := time.Since(pbft.starttime).Seconds()
					fmt.Println("leader", pbft.Id, " informs the new instace the confirmed block at", elapsed, "s")
				}
			} else {
				log.Panic("the config-block has no leave-tx or join-tx")
			}
		} else {
			log.Panic("the height has been executed")
		}
	} else {
		fmt.Println("instance", pbft.Id, "got wrong block type")
	}
}

func (pbft *PBFT) broadcastPubkey() {
	peerid := datastruc.PeerIdentity{pbft.PubKeystr, pbft.Id, pbft.IpPortAddr}
	var buff bytes.Buffer
	enc := gob.NewEncoder(&buff)
	err := enc.Encode(peerid)
	if err != nil {
		log.Panic(err)
	}
	content := buff.Bytes()

	pbft.MsgBuff.Msgbuffmu.Lock()
	pbft.MsgBuff.InitialConfig = append(pbft.MsgBuff.InitialConfig, peerid)
	pbft.MsgBuff.Msgbuffmu.Unlock()


	datatosend := datastruc.Datatosend{pbft.membersexceptme, "idportpubkey", content}

	pbft.broadcdataCh <- datatosend
}

func (pbft *PBFT) broadcastJoinTx(jtx datastruc.JoinTx) {

	var buff bytes.Buffer
	gob.Register(elliptic.P256())
	enc := gob.NewEncoder(&buff)
	err := enc.Encode(jtx)
	if err != nil {
		log.Panic(err)
	}
	content := buff.Bytes()
	datatosend := datastruc.Datatosend{pbft.members, "jointx", content}
	pbft.broadcdataCh <- datatosend
}

func (pbft *PBFT) broadcastLeavingTx() {
	ltx := datastruc.NewLeaveTx(pbft.Id, pbft.IpPortAddr, pbft.PubKeystr, pbft.PriKey)
	var buff bytes.Buffer
	gob.Register(elliptic.P256())
	enc := gob.NewEncoder(&buff)
	err := enc.Encode(ltx)
	if err != nil {
		log.Panic(err)
	}
	content := buff.Bytes()
	//fmt.Println("***** instance", pbft.Id, "sends the original leave-tx, its content", ltx.Serial(), "  its hash", ltx.GetHash(), " its id ", ltx.Id, " its ip addr ", ltx.IpAddr, " its pubkey ", ltx.Pubkey, " its sig ", ltx.Sig)

	pbft.MsgBuff.Msgbuffmu.Lock()
	pbft.MsgBuff.JoinLeavetxSet.LTxSet = append(pbft.MsgBuff.JoinLeavetxSet.LTxSet, ltx)
	pbft.MsgBuff.Msgbuffmu.Unlock()


	datatosend := datastruc.Datatosend{pbft.membersexceptme, "leavetx", content}
	pbft.broadcdataCh <- datatosend
	pbft.censorshipmonitorCh <- ltx.TxHash
}

func (pbft *PBFT) broadcastTxBlock(bloc *datastruc.Block) {
	var buff bytes.Buffer
	enc := gob.NewEncoder(&buff)
	err := enc.Encode(bloc)
	if err != nil {
		log.Panic(err)
	}
	content := buff.Bytes()
	size := len(content) / (1024)
	fmt.Println("the block at height", pbft.currentHeight, "has size", size, "KB")

	pbft.MsgBuff.Msgbuffmu.Lock()
	pbft.MsgBuff.BlockPool = append(pbft.MsgBuff.BlockPool, *bloc)
	pbft.MsgBuff.Msgbuffmu.Unlock()

	datatosend := datastruc.Datatosend{pbft.membersexceptme, "txblock", content}

	pbft.broadcdataCh <- datatosend
}

func (pbft *PBFT) broadcastConfigBlock(bloc *datastruc.Block) {
	var buff bytes.Buffer
	enc := gob.NewEncoder(&buff)
	err := enc.Encode(bloc)
	if err != nil {
		log.Panic(err)
	}
	content := buff.Bytes()

	pbft.MsgBuff.Msgbuffmu.Lock()
	pbft.MsgBuff.BlockPool = append(pbft.MsgBuff.BlockPool, *bloc)
	for _, ltx := range bloc.LeaveTxList {
		if !ltx.Verify() {
			fmt.Println("leader", pbft.Id, "receives a block, but contains unvalid leave-tx, its content", ltx.Serialize(), "  its hash", ltx.TxHash, " its id ", ltx.Id, " its ip addr ", ltx.IpAddr, " its pubkey ", ltx.Pubkey, " its sig ", ltx.Sig)
		}
	}
	pbft.MsgBuff.Msgbuffmu.Unlock()

	datatosend := datastruc.Datatosend{pbft.membersexceptme, "configblock", content}
	pbft.broadcdataCh <- datatosend
}

func (pbft *PBFT) broadcastPreprepare(ver, view, n int, prk *ecdsa.PrivateKey, hashval [32]byte) {
	prepreparemsg := datastruc.NewPreprepareMsg(ver, view, n, pbft.PubKeystr, prk, hashval)
	var buff bytes.Buffer
	enc := gob.NewEncoder(&buff)
	err := enc.Encode(prepreparemsg)
	if err != nil {
		log.Panic(err)
	}
	content := buff.Bytes()

	pbft.MsgBuff.Msgbuffmu.Lock()
	theprog := datastruc.Progres{prepreparemsg.Ver, prepreparemsg.View, prepreparemsg.Order}
	pbft.MsgBuff.Pre_preparelog[theprog] = prepreparemsg
	pbft.MsgBuff.Msgbuffmu.Unlock()

	//fmt.Println("leader", pbft.Id, "broadcasts pre-prepare msg to", pbft.membersexceptme)
	datatosend := datastruc.Datatosend{pbft.membersexceptme, "prepreparemsg", content}
	pbft.broadcdataCh <- datatosend
}

func (pbft *PBFT) broadcastPrepare(ver, view, n int, digest [32]byte) {
	preparemsg := datastruc.NewPrepareMsg(ver, view, n, digest, pbft.PubKeystr, pbft.PriKey)
	var buff bytes.Buffer
	enc := gob.NewEncoder(&buff)
	err := enc.Encode(preparemsg)
	if err != nil {
		log.Panic(err)
	}
	content := buff.Bytes()

	pbft.MsgBuff.Msgbuffmu.Lock()
	theterm := datastruc.Term{preparemsg.Ver, preparemsg.View}
	theorder := preparemsg.Order
	if _, ok := pbft.MsgBuff.PrepareVote[theterm]; !ok {
		pbft.MsgBuff.PrepareVote[theterm] = make(map[int][]datastruc.PrepareMsg)
	}
	pbft.MsgBuff.PrepareVote[theterm][theorder] = append(pbft.MsgBuff.PrepareVote[theterm][theorder], preparemsg)
	pbft.MsgBuff.Msgbuffmu.Unlock()

	datatosend := datastruc.Datatosend{pbft.membersexceptme, "preparemsg", content}
	pbft.broadcdataCh <- datatosend
	//fmt.Println("instance", pbft.Id, "broadcasts prepare-vote in height", n)
}

func (pbft *PBFT) broadcastCommit(ver, view, n int, digest [32]byte) {
	commitmsg := datastruc.NewCommitMsg(ver, view, n, digest, pbft.PubKeystr, pbft.PriKey)
	var buff bytes.Buffer
	enc := gob.NewEncoder(&buff)
	err := enc.Encode(commitmsg)
	if err != nil {
		log.Panic(err)
	}
	content := buff.Bytes()

	pbft.MsgBuff.Msgbuffmu.Lock()
	theterm := datastruc.Term{commitmsg.Ver, commitmsg.View}
	theorder := commitmsg.Order
	if _, ok := pbft.MsgBuff.CommitVote[theterm]; !ok {
		pbft.MsgBuff.CommitVote[theterm] = make(map[int][]datastruc.CommitMsg)
	}
	pbft.MsgBuff.CommitVote[theterm][theorder] = append(pbft.MsgBuff.CommitVote[theterm][theorder], commitmsg)
	pbft.MsgBuff.Msgbuffmu.Unlock()

	datatosend := datastruc.Datatosend{pbft.membersexceptme, "commitmsg", content}
	pbft.broadcdataCh <- datatosend
}

func (pbft *PBFT) broadcastViewChange(ver int, view int, ltxset []datastruc.LeaveTx, plock datastruc.PreparedLock,
	clock datastruc.CommitedLock, pubkey string, prvkey *ecdsa.PrivateKey) {
	//ltxset = []datastruc.LeaveTx{} // mechanism2
	var vcmsg datastruc.ViewChangeMsg

	if clock.LockedHeight >0 {
		vcmsg = datastruc.NewViewChangeMsg(ver, view, pbft.Id, ltxset, clock.LockedHeight, plock, clock, pubkey, prvkey)
		fmt.Println("instance",pbft.Id, "creates a view-change msg at ver", ver, "view", view, "with commit-lock at height", vcmsg.Clock.LockedHeight, "with digest", vcmsg.Clock.LockedHash[0:6])
	} else {
		vcmsg = datastruc.NewViewChangeMsg(ver, view, pbft.Id, ltxset, plock.LockedHeight, plock, clock, pubkey, prvkey)
		fmt.Println("instance",pbft.Id, "creates a view-change msg at ver", ver, "view", view, "with prepare-lock at height", vcmsg.Plock.LockedHeight, "with digest", vcmsg.Plock.LockedHash[0:6])
	}
	var buff bytes.Buffer
	enc := gob.NewEncoder(&buff)
	err := enc.Encode(vcmsg)
	if err!=nil {
		log.Panic(err)
	}
	content := buff.Bytes()

	pbft.MsgBuff.Msgbuffmu.Lock()
	theterm := datastruc.Term{vcmsg.Ver, vcmsg.View}
	pbft.MsgBuff.Vcmsg[theterm] = append(pbft.MsgBuff.Vcmsg[theterm], vcmsg)
	pbft.MsgBuff.Msgbuffmu.Unlock()

	datatosend := datastruc.Datatosend{pbft.membersexceptme, "viewchangemsg", content}
	//fmt.Println("instance", pbft.Id, "broadcasts the view chagne msg to", pbft.membersexceptme)
	pbft.broadcdataCh <- datatosend
	fmt.Println("instance", pbft.Id, "broadcast view-change msg at ver", vcmsg.Ver, "view", vcmsg.View, "to", pbft.membersexceptme)
}

func (pbft *PBFT) decideNewViewMsgKind(vcset []datastruc.ViewChangeMsg) (string, datastruc.Block){
	var thekind string
	var bloc datastruc.Block

	hasltx := false
	var theltx datastruc.LeaveTx
	for _, vcmsg := range vcset {
		if len(vcmsg.LtxSet)>0 {
			hasltx = true
			theltx = vcmsg.LtxSet[0]
			break
		}
	}

	if hasltx {
		thekind = "withblock"
		maxlockheight := 0
		for _, vcmsg := range vcset {
			maxlockheight = datastruc.Takemax(maxlockheight, vcmsg.Lockheight)
		}
		proposeheight := maxlockheight+1  // height of the config-block including the theltx

		// pack config-block at proposeheight
		if pbft.persis.commitlock.LockedHeight==maxlockheight {
			// means it can directly pack a new config-block
			peers := datastruc.GenerateNewConfigForLeave(pbft.succLine.ConverToList(), theltx)
			bloc = datastruc.NewLeaveConfigBlock(pbft.PubKeystr, pbft.PriKey, theltx, peers, proposeheight, pbft.vernumber,
				pbft.persis.blockhashlist[pbft.persis.commitlock.LockedHeight])
		} else {
			//fmt.Println("leader can't pack config-block for the leave-tx because it's left behind")
			log.Panic("leader ", pbft.Id, " can't pack config-block for the leave-tx because it's left behind")
		}
		if pbft.isbyzantine {
			fmt.Println("byzantine leader", pbft.Id, "honestly adds leave-tx when packing new-view message")
		}
	} else {
		thekind = "withoutblock"
	}
	return thekind, bloc
}

func (pbft *PBFT) broadcastNewViewWithoutBlock(ver int, view int, vcset []datastruc.ViewChangeMsg) {
	nvmsg := datastruc.NewNewViewMsgWithoutBlock(ver, view, pbft.PubKeystr, vcset, pbft.PriKey)
	var order int
	if nvmsg.Clock.LockedHeight > 0 {
		order = nvmsg.Clock.LockedHeight
		fmt.Println("leader", pbft.Id, "now broadcasts new-view msg, with only commit-lock but no prepare-lock, committed at height", order)
	} else {
		order = nvmsg.PPMsgSet[0].Order
		fmt.Println("leader", pbft.Id, "now broadcasts new-view msg, with only prepare-lock but no commit-lock, prepared at height", order)
	}
	var buff bytes.Buffer
	enc := gob.NewEncoder(&buff)
	err := enc.Encode(nvmsg)
	if err!=nil {
		log.Panic(err)
	}
	content := buff.Bytes()

	pbft.MsgBuff.Msgbuffmu.Lock()
	theterm := datastruc.Term{nvmsg.Ver, nvmsg.View}
	pbft.MsgBuff.Newviewlog[theterm] = nvmsg
	pbft.MsgBuff.Msgbuffmu.Unlock()

	datatosend := datastruc.Datatosend{pbft.membersexceptme, "newviewmsg", content}
	pbft.broadcdataCh <- datatosend
}

func (pbft *PBFT) broadcastNewViewWithBlock(ver int, view int, vcset []datastruc.ViewChangeMsg, bloc datastruc.Block) {
	nvmsg := datastruc.NewNewViewMsgWithBlock(ver, view, pbft.PubKeystr, vcset, pbft.PriKey, bloc)
	order := nvmsg.Bloc.Blockhead.Height
	fmt.Println("leader", pbft.Id, "now broadcasts new-view msg, with only commit-lock and new config-block for leave-tx at height", order)
	var buff bytes.Buffer
	enc := gob.NewEncoder(&buff)
	err := enc.Encode(nvmsg)
	if err!=nil {
		log.Panic(err)
	}
	content := buff.Bytes()

	pbft.MsgBuff.Msgbuffmu.Lock()
	theterm := datastruc.Term{nvmsg.Ver, nvmsg.View}
	pbft.MsgBuff.Newviewlog[theterm] = nvmsg
	pbft.MsgBuff.BlockPool = append(pbft.MsgBuff.BlockPool, bloc)
	thepreprepare := nvmsg.PPMsgSet[0]
	theprog := datastruc.Progres{thepreprepare.Ver, thepreprepare.View, thepreprepare.Order}
	pbft.MsgBuff.Pre_preparelog[theprog] = thepreprepare
	pbft.MsgBuff.Msgbuffmu.Unlock()

	datatosend := datastruc.Datatosend{pbft.membersexceptme, "newviewmsg", content}
	pbft.broadcdataCh <- datatosend
}


func (pbft *PBFT) broadcastCheckPoint(ckpm datastruc.CheckPointMsg) {
	var buff bytes.Buffer
	enc := gob.NewEncoder(&buff)
	err := enc.Encode(ckpm)
	if err != nil {
		log.Panic(err)
	}
	content := buff.Bytes()

	pbft.MsgBuff.Msgbuffmu.Lock()
	h := ckpm.Height
	pbft.MsgBuff.CheckpointVote[h] = append(pbft.MsgBuff.CheckpointVote[h], ckpm)
	pbft.MsgBuff.Msgbuffmu.Unlock()

	datatosend := datastruc.Datatosend{pbft.membersexceptme, "checkpointmsg", content}
	pbft.broadcdataCh <- datatosend
}


func (pbft *PBFT) InformNewPeer(cbloc datastruc.ConfirmedBlock,dest int) {
	var buff bytes.Buffer
	gob.Register(elliptic.P256())
	enc := gob.NewEncoder(&buff)
	err := enc.Encode(cbloc)
	if err!=nil {
		log.Panic()
	}
	content := buff.Bytes()
	destlist := make([]int, 0)
	destlist = append(destlist, dest)
	datatosend := datastruc.Datatosend{destlist, "confirmedblock", content}
	pbft.broadcdataCh <- datatosend
}

func (pbft *PBFT) waitForConfirmedBlock() datastruc.ConfirmedBlock {
	var cbloc datastruc.ConfirmedBlock
	cbloc = pbft.scanConfirmedBlock()
	fmt.Println("instance", pbft.Id, "has got confirmed block after waitting")
	return cbloc
}

func (pbft *PBFT) waitForStateTransferReply(height int) map[string]int {
	// the height is the confirmed block's height-1, the state-transfer-reply must be at the same value
	balance := make(map[string]int)
	for {
		select {
		case rstmsg :=<- pbft.statetransferreplyCh:
			if rstmsg.Height==height {
				fmt.Println("instance", pbft.Id, "receives a state-transfer-reply at height", rstmsg.Height)
				balance = rstmsg.AccountBalance
				if rstmsg.CheckPointHeight<height-1 {
					for _,block:=range rstmsg.BlockList {
						for _, tx := range block.TransactionList {
							balance[tx.Source] -= tx.Value
							balance[tx.Recipient] += tx.Value
						}
					}
				}
				return balance
			}
		}
	}
}

func (pbft *PBFT) QueryStateTransfer(heigh int, dest int) {
	// heigh means that: I've the block at heigh, please send me the latest checkpoint and blocks from the checkpoint to heigh
	querymsg := datastruc.NewQueryStateTransfer(pbft.Id, heigh, pbft.PubKeystr, pbft.PriKey)
	var buff bytes.Buffer
	enc := gob.NewEncoder(&buff)
	err := enc.Encode(querymsg)
	if err!=nil {
		log.Panic(err)
	}
	content := buff.Bytes()
	destlist := make([]int, 0)
	destlist = append(destlist, dest)
	datatosend := datastruc.Datatosend{destlist, "querystatetran", content}
	pbft.broadcdataCh <- datatosend
}

func (pbft *PBFT) ReplyStateTransfer(height, id int) {
	// find most recent checkpoint.
	ckph := pbft.persis.checkpointheight
	var blocklist []datastruc.Block
	if ckph>=height-1 {
		// do nothing, keep blocklist empty
	} else if ckph<height-1  {
		blocklist = pbft.cachedb.ReadBlockFromDB(ckph+1, height-1)
	} else {
		fmt.Println("state transfer queried height is not valid")
	}

	replymsg := datastruc.NewReplyStateTransfer(height, ckph, pbft.cachedb.ReadAccountBalanceAtHeight(ckph), blocklist, pbft.PubKeystr, pbft.PriKey)
	var buff bytes.Buffer
	enc := gob.NewEncoder(&buff)
	err := enc.Encode(replymsg)
	if err!=nil {
		log.Panic(err)
	}
	content := buff.Bytes()
	destlist := make([]int, 0)
	destlist = append(destlist, id)
	datatosend := datastruc.Datatosend{destlist, "replystatetran", content}
	pbft.broadcdataCh <- datatosend
	fmt.Println("instance", pbft.Id, "sends state-transfer-reply to instance", id, "from checkpoint height", ckph,
		"to height", height, "which the querier has, including", len(blocklist), "blocks in it")
}

func (pbft *PBFT) broadcastMeasurementResult(mrmsg datastruc.MeasurementResultMsg) {
	var buff bytes.Buffer
	gob.Register(elliptic.P256())
	enc := gob.NewEncoder(&buff)
	err := enc.Encode(mrmsg)
	if err != nil {
		log.Panic("measurement msg encode error")
	}
	content := buff.Bytes()

	pbft.MsgBuff.Msgbuffmu.Lock()
	hval := mrmsg.GetHash()
	pbft.MsgBuff.MeasurementResPool[hval] = mrmsg
	pbft.MsgBuff.Msgbuffmu.Unlock()

	datatosend := datastruc.Datatosend{pbft.membersexceptme, "measurement", content}
	pbft.broadcdataCh <- datatosend
}

//func EvaluateCapacity(res1 []int, res2 []int, q int) bool {
//	coun1 := 0
//	for _, v := range res1 {
//		if v < JOININGTHRES {
//			coun1 += 1
//		}
//	}
//	coun2 := 0
//	for _, v := range res2 {
//		if v < JOININGTHRES {
//			coun2 += 1
//		}
//	}
//	return (coun1>=q)&&(coun2>=q)
//}

func EvaluateCapacity(resselfasleader []int, resnewasleader []int, selfid int, newid int) bool {
	//return resselfasleader[newid]<JOININGTHRES && resnewasleader[selfid]<JOININGTHRES
	return true
}

func (pbft *PBFT) computeTps() {

	for {
		pbft.mu.Lock()
		elapsedtime := time.Since(pbft.tpsstarttime).Seconds()
		tps := float64(pbft.acctx)/elapsedtime
		pbft.tps = append(pbft.tps, int(tps))
		//le := len(pbft.tps)
		//if le%2==0 {
		//	fmt.Println("instance", pbft.Id, "tps at", time.Since(pbft.starttime).Seconds(), "s is", pbft.tps[le-1])
		//}
		pbft.mu.Unlock()
		time.Sleep(time.Millisecond * 500)
	}
}

func (pbft *PBFT) Stop() {
	pbft.stopCh<-true
	pbft.stopCh<-true
	fmt.Println("end-------------------------------")
	fmt.Println("instance", pbft.Id, "blocks here permanentally, test ends time", time.Since(pbft.starttime).Seconds(), "s")
	fmt.Println("tps starttime is", pbft.tpsstarttime.Sub(pbft.starttime).Seconds(), "s, total processed tx is", pbft.acctx,
		"total elapsed time is", time.Since(pbft.tpsstarttime).Seconds(), "s, average tps is",
		float64(pbft.acctx)/float64(time.Since(pbft.tpsstarttime).Seconds()))
	fmt.Println("tps =", pbft.tps)
	fmt.Println("leader =", pbft.leaderlog)
	fmt.Println("consensustime =", pbft.consensustimelog)
	fmt.Println("predictedconsensustime =", pbft.predictedconsensustimelog)

	fmt.Println("viewchagnetime =", pbft.viewchangetimelog)
	fmt.Println("inauguratetime =", pbft.inauguratetimelog)
	pbft.cdedata.Sanitization()
	pbft.cdedata.PrintResult()
	time.Sleep(time.Second * 100)
}