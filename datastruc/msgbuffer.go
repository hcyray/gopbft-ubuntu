package datastruc

import (
	"fmt"
	"sync"
	"time"
)

type Term struct {
	Ver int
	View int
}

type Progres struct {
	Ver int
	View int
	Height int
}

type MessageBuffer struct {
	Msgbuffmu sync.Mutex

	InitialConfig []PeerIdentity
	TxPool map[[32]byte]Transaction
	JoinLeavetxSet JLTxSet
	BlockPool []Block
	ConfirmedBlockPool []ConfirmedBlock

	Pre_preparelog map[Progres]PrePrepareMsg // height -> msg
	Newviewlog map[Term]NewViewMsg // (ver, view) -> msg
	PrepareVote map[Term]map[int][]PrepareMsg // (ver, view) -> map[height]msgset
	CommitVote map[Term]map[int][]CommitMsg // (ver, view) -> map[height]msgset
	Vcmsg map[Term][]ViewChangeMsg // (ver, view) -> msgset
	CheckpointVote map[int][]CheckPointMsg // height -> msg

	AccountBalance map[string]int
	MeasurementResPool map[[32]byte]MeasurementResultMsg
	CurConfig []PeerIdentity
}

func (msgbuf *MessageBuffer) Initialize() {
	msgbuf.InitialConfig = make([]PeerIdentity, 0)
	msgbuf.TxPool = make(map[[32]byte]Transaction)
	msgbuf.BlockPool = make([]Block, 0)

	msgbuf.Pre_preparelog = make(map[Progres]PrePrepareMsg)
	msgbuf.Newviewlog = make(map[Term]NewViewMsg)
	msgbuf.PrepareVote = make(map[Term]map[int][]PrepareMsg)
	msgbuf.CommitVote = make(map[Term]map[int][]CommitMsg)
	msgbuf.Vcmsg = make(map[Term][]ViewChangeMsg)
	msgbuf.CheckpointVote = make(map[int][]CheckPointMsg)
	msgbuf.AccountBalance = make(map[string]int)

	msgbuf.MeasurementResPool = make(map[[32]byte]MeasurementResultMsg)
}

func (msgbuf *MessageBuffer) ClearTXPool() {
	msgbuf.Msgbuffmu.Lock()
	defer msgbuf.Msgbuffmu.Unlock()

	fmt.Println("instance clear tx pool, discard", len(msgbuf.TxPool),"txs")
	msgbuf.TxPool = make(map[[32]byte]Transaction)
}

func (msgbuf *MessageBuffer) ReadConfirmedBlock() (bool, ConfirmedBlock) {
	msgbuf.Msgbuffmu.Lock()
	defer msgbuf.Msgbuffmu.Unlock()

	var cbloc ConfirmedBlock
	if len(msgbuf.ConfirmedBlockPool)>0 {
		cbloc = msgbuf.ConfirmedBlockPool[0]
		return true, cbloc
	}
	return false, cbloc
}

func (msgbuf *MessageBuffer) ReadInitialConfig(targetnum int) (bool, []PeerIdentity) {
	msgbuf.Msgbuffmu.Lock()
	defer msgbuf.Msgbuffmu.Unlock()

	if len(msgbuf.InitialConfig)==targetnum {
		return true, msgbuf.InitialConfig
	}
	return false, []PeerIdentity{}
}

func (msgbuf *MessageBuffer) SearchBlock(blockhash [32]byte) (bool, *Block) {
	msgbuf.Msgbuffmu.Lock()
	defer msgbuf.Msgbuffmu.Unlock()
	var pblock *Block

	for _, bloc := range msgbuf.BlockPool {
		if TwoHashEqual(blockhash, bloc.GetHash()) {
			pblock = &bloc
			return true, pblock
		}
	}
	return false, pblock
}

func (msgbuf *MessageBuffer) ReadTxBatch(volume int) []Transaction {
	// ensure that the tx batch is valid when executing from the beginning to the end
	msgbuf.Msgbuffmu.Lock()
	defer msgbuf.Msgbuffmu.Unlock()

	starttime := time.Now()
	thetxpool := []Transaction{}
	currbalance := make(map[string]int)
	for k, v := range msgbuf.AccountBalance {
		currbalance[k] = v
	}
	i := 0
	for _, tx := range msgbuf.TxPool {

		if currbalance[tx.Source]>= tx.Value {
			thetxpool = append(thetxpool, tx)
			i += 1
			if i>=volume{
				break
			}
			currbalance[tx.Source] -= tx.Value
			currbalance[tx.Recipient] += tx.Value
		}

	}
	elapsed := time.Since(starttime).Milliseconds()
	fmt.Println("read tx from buffer costs", elapsed, "ms")
	return thetxpool
}

func (msgbuf *MessageBuffer) ReadLeaveTx() []LeaveTx {
	msgbuf.Msgbuffmu.Lock()
	defer msgbuf.Msgbuffmu.Unlock()

	ltx := msgbuf.JoinLeavetxSet.LTxSet
	return ltx
}

func (msgbuf *MessageBuffer) ReadJoinTx() []JoinTx {
	msgbuf.Msgbuffmu.Lock()
	defer msgbuf.Msgbuffmu.Unlock()

	jtx := msgbuf.JoinLeavetxSet.JTxset
	return jtx
}

func (msgbuf *MessageBuffer) ReadPrepreparelog(theprog Progres) (PrePrepareMsg, bool) {
	msgbuf.Msgbuffmu.Lock()
	defer msgbuf.Msgbuffmu.Unlock()

	thepreprepare, ok := msgbuf.Pre_preparelog[theprog]
	return thepreprepare, ok
}

func (msgbuf *MessageBuffer) ReadPrepareVoteQuorum(theterm Term, heigh int, quorumsize int) []PrepareMsg {
	msgbuf.Msgbuffmu.Lock()
	defer msgbuf.Msgbuffmu.Unlock()

	res := msgbuf.PrepareVote[theterm][heigh][0:quorumsize]
	return res
}

func (msgbuf *MessageBuffer) CountPrepareVote(theterm Term, heigh int, digest [32]byte) int {
	msgbuf.Msgbuffmu.Lock()
	defer msgbuf.Msgbuffmu.Unlock()

	acc := 0
	for _, vote := range msgbuf.PrepareVote[theterm][heigh] {
		if TwoHashEqual(digest,vote.Digest) {
			acc += 1
		} else {
			fmt.Println("prepare vote digest not match, vote digest is ", vote.Digest[0:6])
		}
	}
	return acc
}

func (msgbuf *MessageBuffer) CountCommitVote(theterm Term, heigh int, digest [32]byte) int {
	msgbuf.Msgbuffmu.Lock()
	defer msgbuf.Msgbuffmu.Unlock()

	acc := 0
	if len(msgbuf.CommitVote[theterm][heigh])==0 {
		//fmt.Println("commit vote buffer at term ", theterm, " height ", heigh, "is empty")
	} else {
		//fmt.Println("commit vote buffer at term ", theterm, " height ", heigh, "has ", len(msgbuf.CommitVote[theterm][heigh]), "commit vote")
		for _, vote := range msgbuf.CommitVote[theterm][heigh] {
			if TwoHashEqual(digest,vote.Digest) {
				acc += 1
				//fmt.Println("commit vote ", i, " digest matches, vote digest is ", vote.Digest[0:6], " vote ver ", vote.Ver, " vote view ", vote.View, " vote order ", vote.Order)
			} else {
				//fmt.Println("commit vote ", i, " digest not match, vote digest is ", vote.Digest[0:6], " vote ver ", vote.Ver, " vote view ", vote.View, " vote order ", vote.Order)
			}
		}
	}
	return acc
}

func (msgbuf *MessageBuffer) CountCheckpointVote(h int, syshash [32]byte) int {
	msgbuf.Msgbuffmu.Lock()
	defer msgbuf.Msgbuffmu.Unlock()

	acc := 0
	for _, vote := range msgbuf.CheckpointVote[h] {
		if TwoHashEqual(syshash, vote.Syshash) {
			acc += 1
		}
	}
	return acc
}

func (msgbuf *MessageBuffer) ReadCommitVoteQuorum(theterm Term, heigh int, quorumsize int) []CommitMsg {
	msgbuf.Msgbuffmu.Lock()
	defer msgbuf.Msgbuffmu.Unlock()

	res := msgbuf.CommitVote[theterm][heigh][0:quorumsize]
	return res
}

func (msgbuf *MessageBuffer) CountViewChangeVote(theterm Term) int {
	msgbuf.Msgbuffmu.Lock()
	defer msgbuf.Msgbuffmu.Unlock()

	le := len(msgbuf.Vcmsg[theterm])
	return le
}

func (msgbuf *MessageBuffer) ReadViewChangeQuorum(theterm Term, quorumsize int) []ViewChangeMsg {
	msgbuf.Msgbuffmu.Lock()
	defer msgbuf.Msgbuffmu.Unlock()

	res := msgbuf.Vcmsg[theterm][0:quorumsize]
	return res
}

func (msgbuf *MessageBuffer) ReadNewViewlog(theterm Term) (NewViewMsg, bool) {
	msgbuf.Msgbuffmu.Lock()
	defer msgbuf.Msgbuffmu.Unlock()

	thepreprepare, ok := msgbuf.Newviewlog[theterm]
	return thepreprepare, ok
}

func (msgbuf *MessageBuffer) ReadMeasuremenResBatch() []MeasurementResultMsg {
	msgbuf.Msgbuffmu.Lock()
	defer msgbuf.Msgbuffmu.Unlock()

	res := make([]MeasurementResultMsg, 0)
	for _, v := range msgbuf.MeasurementResPool {
		res = append(res, v)
	}
	return res
}

func (msgbuf *MessageBuffer) UpdateMeasurementResAfterCommitBlock(bloc *Block) {
	msgbuf.Msgbuffmu.Lock()
	defer msgbuf.Msgbuffmu.Unlock()

	for _, mr := range bloc.MeasurementResList {
		delete(msgbuf.MeasurementResPool, mr.GetHash())
	}
}

func (msgbuf *MessageBuffer) InitializeVoteMap(theterm Term) {
	msgbuf.Msgbuffmu.Lock()
	defer msgbuf.Msgbuffmu.Unlock()

	if _, ok := msgbuf.PrepareVote[theterm]; ! ok {
		msgbuf.PrepareVote[theterm] = make(map[int][]PrepareMsg)
	}
	if _, ok := msgbuf.CommitVote[theterm]; !ok {
		msgbuf.CommitVote[theterm] = make(map[int][]CommitMsg)
	}
}

func (msgbuf *MessageBuffer) UpdateTxPoolAfterCommitBlock(bloc *Block) {
	msgbuf.Msgbuffmu.Lock()
	defer msgbuf.Msgbuffmu.Unlock()
	for _, tx := range bloc.TransactionList {
		delete(msgbuf.TxPool, tx.GetHash())
	}
}

func (msgbuf *MessageBuffer) UpdateJoinLeaveTxSetAfterCommitBlock(bloc *Block) {
	msgbuf.Msgbuffmu.Lock()
	defer msgbuf.Msgbuffmu.Unlock()

	if len(bloc.LeaveTxList)>0 {
		theltx := bloc.LeaveTxList[0]
		ltxlist := make([]LeaveTx, 0)
		for _, ltx := range msgbuf.JoinLeavetxSet.LTxSet {
			if !TwoHashEqual(theltx.TxHash, ltx.TxHash) {
				ltxlist = append(ltxlist, ltx)
			}
		}
		msgbuf.JoinLeavetxSet.LTxSet = ltxlist
	}
	if len(bloc.JoinTxList)>0 {
		thejtx := bloc.JoinTxList[0]
		jtxlist := make([]JoinTx, 0)
		for _, jtx := range msgbuf.JoinLeavetxSet.JTxset {
			if !TwoHashEqual(thejtx.TxHash, jtx.TxHash) {
				jtxlist = append(jtxlist, jtx)
			}
		}
		msgbuf.JoinLeavetxSet.JTxset = jtxlist
	}
}

func (msgbuf *MessageBuffer) UpdateBlockPoolAfterCommitBlock(bloc *Block) {
	msgbuf.Msgbuffmu.Lock()
	defer msgbuf.Msgbuffmu.Unlock()

	newblocklist := []Block{}
	for _, block := range msgbuf.BlockPool {
		if TwoHashEqual(bloc.GetHash(), block.GetHash()) {
			newblocklist = append(newblocklist, block)
		}
	}
	msgbuf.BlockPool = newblocklist
}

func (msgbuf *MessageBuffer) UpdateConfirmedBlockPool(cbloc *ConfirmedBlock) {
	msgbuf.Msgbuffmu.Lock()
	defer msgbuf.Msgbuffmu.Unlock()


	newcblocklist := []ConfirmedBlock{}
	for _, cblock := range msgbuf.ConfirmedBlockPool {
		if TwoHashEqual(cblock.PreppMsg.Digest, cbloc.PreppMsg.Digest) {
			newcblocklist = append(newcblocklist, cblock)
		}
	}
	msgbuf.ConfirmedBlockPool = newcblocklist

}

func (msgbuf *MessageBuffer) ConfigTxIsEmpty() string {
	msgbuf.Msgbuffmu.Lock()
	defer msgbuf.Msgbuffmu.Unlock()

	var res string
	a := len(msgbuf.JoinLeavetxSet.JTxset)
	b := len(msgbuf.JoinLeavetxSet.LTxSet)
	if b==0 {
		if a==0 {
			res = "bothempty"
		} else {
			res = "jointxexists"
		}
	} else {
		res = "leavetxexists"
	}

	return res
}

func (msgbuf *MessageBuffer) UpdateCurConfig(curconfig []PeerIdentity) {
	msgbuf.Msgbuffmu.Lock()
	defer msgbuf.Msgbuffmu.Unlock()

	msgbuf.CurConfig = make([]PeerIdentity, len(curconfig))
	copy(msgbuf.CurConfig, curconfig)
}

func (msgbuf *MessageBuffer) UpdateBalance(accb map[string]int) {
	msgbuf.Msgbuffmu.Lock()
	defer msgbuf.Msgbuffmu.Unlock()

	for k, v := range accb {
		msgbuf.AccountBalance[k] = v
	}
}

func (msgbuf *MessageBuffer) DeleteWeakJoinRequest() {
	msgbuf.Msgbuffmu.Lock()
	defer msgbuf.Msgbuffmu.Unlock()

	// actually, the join-tx buffer is cleared
	// todo, need further refine
	msgbuf.JoinLeavetxSet.JTxset = []JoinTx{}
}