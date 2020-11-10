package cachedb

import (
	"../datastruc"
	"fmt"
	"sync"
)


type BlockChainCacheDB struct {
	dbmu sync.Mutex

	InstanceId int
	BucketMarginalInfo map[string]int
	BucketHeighttoHash map[int][32]byte
	BucketHashToBlock map[[32]byte]datastruc.Block
	BucketNumToConfgi map[int][]datastruc.PeerIdentity
	//BucketCurUTXO []datastruc.UTXO
	BucketPrepareQC map[[32]byte]datastruc.PrepareQC
	BucketCommitQC map[[32]byte]datastruc.CommitQC
	BucketAccountBalanceHistory map[int]map[string]int
}

func (bccdb *BlockChainCacheDB) Initialize(id int) {
	//bccdb.dbmu.Lock()
	//defer bccdb.dbmu.Unlock()

	bccdb.InstanceId = id
	bccdb.BucketMarginalInfo = make(map[string]int)
	bccdb.BucketHeighttoHash = make(map[int][32]byte)
	bccdb.BucketHashToBlock = make(map[[32]byte]datastruc.Block)
	bccdb.BucketNumToConfgi = make(map[int][]datastruc.PeerIdentity)
	//bccdb.BucketCurUTXO = make([]datastruc.UTXO, 0)
	bccdb.BucketPrepareQC = make(map[[32]byte]datastruc.PrepareQC)
	bccdb.BucketCommitQC = make(map[[32]byte]datastruc.CommitQC)
	bccdb.BucketAccountBalanceHistory = make(map[int]map[string]int)
}

func (bccdb *BlockChainCacheDB) UpdateFromGenesisb(genesis datastruc.Block) {
	bccdb.dbmu.Lock()
	defer bccdb.dbmu.Unlock()

	bccdb.BucketMarginalInfo["recentConfigVer"] = 0
	bccdb.BucketMarginalInfo["commiHeight"] = 0

	bccdb.BucketHeighttoHash[0] = genesis.GetHash()

	bccdb.BucketHashToBlock[genesis.GetHash()] = genesis

	bccdb.BucketNumToConfgi[0] = genesis.Configure

	//for _, tx := range genesis.TransactionList {
	//	pub := tx.Vout[0].PubKey
	//	value := tx.Vout[0].Value
	//	theutxo :=  datastruc.UTXO{tx, pub, value}
	//	bccdb.BucketCurUTXO = append(bccdb.BucketCurUTXO, theutxo)
	//}

	bccdb.BucketPrepareQC[genesis.GetHash()] = datastruc.PrepareQC{}
	bccdb.BucketCommitQC[genesis.GetHash()] = datastruc.CommitQC{}
}

func (bccdb *BlockChainCacheDB) UpdateAfterPrepare(heigh int, blockhash [32]byte, prepareqc datastruc.PrepareQC) {
	bccdb.dbmu.Lock()
	defer bccdb.dbmu.Unlock()

	bccdb.BucketMarginalInfo["preparedHeight"] = heigh
	bccdb.BucketPrepareQC[blockhash] = prepareqc
}

func (bccdb *BlockChainCacheDB) UpdateAfterCommit(heigh int, block *datastruc.Block, accountbalance map[string]int, commitqc datastruc.CommitQC) {
	bccdb.dbmu.Lock()
	defer bccdb.dbmu.Unlock()

	if block.Blockhead.Kind=="txblock" {
		bccdb.BucketMarginalInfo["commitHeight"] = heigh
		bccdb.BucketHeighttoHash[heigh] = block.GetHash()
		bccdb.BucketHashToBlock[block.GetHash()] = *block
		//bccdb.BucketCurUTXO = []datastruc.UTXO{}
		//bccdb.BucketCurUTXO = curUtxo.Set
		bccdb.BucketCommitQC[block.GetHash()] = commitqc
		bccdb.BucketAccountBalanceHistory[heigh] = accountbalance
	} else if block.Blockhead.Kind=="configblock" {
		bccdb.BucketMarginalInfo["commitHeigh"] = heigh
		v := bccdb.BucketMarginalInfo["recentConfigVer"] + 1
		bccdb.BucketMarginalInfo["recentConfigVer"] = v
		bccdb.BucketNumToConfgi[v] = block.Configure
		bccdb.BucketHeighttoHash[heigh] = block.GetHash()
		bccdb.BucketHashToBlock[block.GetHash()] = *block
		bccdb.BucketCommitQC[block.GetHash()] = commitqc
	} else {
		fmt.Println("the block has wrong type!")
		return
	}
}

func (bccdb *BlockChainCacheDB) UpdateAfterConfirmB(cbloc datastruc.ConfirmedBlock) {
	bccdb.dbmu.Lock()
	defer bccdb.dbmu.Unlock()

	bccdb.BucketMarginalInfo["commitHeight"] = cbloc.Bloc.Blockhead.Height
	ver := cbloc.Bloc.Blockhead.Ver+1
	bccdb.BucketMarginalInfo["recentConfigVer"] = ver

	bccdb.BucketNumToConfgi[ver] = cbloc.Bloc.Configure
	bccdb.BucketHeighttoHash[cbloc.Bloc.Blockhead.Height] = cbloc.Bloc.GetHash()
	bccdb.BucketHashToBlock[cbloc.Bloc.GetHash()] = cbloc.Bloc
	bccdb.BucketCommitQC[cbloc.Bloc.GetHash()] = cbloc.CommiQC

	// todo, accountbalance
}

func (bccdb *BlockChainCacheDB) ReadBlockFromDB(startheigh int, endheigh int) []datastruc.Block {
	bccdb.dbmu.Lock()
	defer bccdb.dbmu.Unlock()

	res := make([]datastruc.Block, 0)
	for i:=startheigh; i<=endheigh; i++ {
		hashv := bccdb.BucketHeighttoHash[i]
		bloc := bccdb.BucketHashToBlock[hashv]
		res = append(res, bloc)
	}
	return res
}

func (bccdb *BlockChainCacheDB) ReadBlockHeadFromDB(heigh int) datastruc.BlockHead {
	bccdb.dbmu.Lock()
	defer bccdb.dbmu.Unlock()

	res := datastruc.BlockHead{}
	hashv := bccdb.BucketHeighttoHash[heigh]
	bloc := bccdb.BucketHashToBlock[hashv]
	res = bloc.Blockhead
	return res
}

func (bccdb *BlockChainCacheDB) ReadPrepareQCFromDB(startheigh int, endheigh int) []datastruc.PrepareQC {
	bccdb.dbmu.Lock()
	defer bccdb.dbmu.Unlock()

	res := make([]datastruc.PrepareQC, 0)
	for i:=startheigh; i<=endheigh; i++ {
		hashv := bccdb.BucketHeighttoHash[i]
		ppqc := bccdb.BucketPrepareQC[hashv]
		res = append(res, ppqc)
	}
	return res
}

func (bccdb *BlockChainCacheDB) ReadCommitQCFromDB(startheigh int, endheigh int) []datastruc.CommitQC {
	bccdb.dbmu.Lock()
	defer bccdb.dbmu.Unlock()

	res := make([]datastruc.CommitQC, 0)
	for i:=startheigh; i<=endheigh; i++ {
		hashv := bccdb.BucketHeighttoHash[i]
		cmqc := bccdb.BucketCommitQC[hashv]
		res = append(res, cmqc)
	}
	return res
}

func (bccdb *BlockChainCacheDB) ReadAccountBalanceAtHeight(height int) map[string]int {
	bccdb.dbmu.Lock()
	defer bccdb.dbmu.Unlock()

	res := make(map[string]int)
	res = bccdb.BucketAccountBalanceHistory[height]
	return res
}
