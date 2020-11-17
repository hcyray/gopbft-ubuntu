package datastruc

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/gob"
	"fmt"
	"log"
)

type PrePrepareMsg struct {
	Ver int
	View int
	Order int
	Digest [32]byte
	Pubkey string
	Sig PariSign
}

type PrepareMsg struct {
	Ver int
	View int
	Order int
	Digest [32]byte
	Pubkey string
	Sig PariSign
}

type CommitMsg struct {
	Ver int
	View int
	Order int
	Digest [32]byte
	Pubkey string
	Sig PariSign
}

type ViewChangeMsg struct {
	Ver int
	View int

	Ckpheight int
	Ckpqc CheckPointQC
	Plock PreparedLock
	Clock CommitedLock

	LtxSet []LeaveTx

	Pubkey string
	Sig PariSign
}

type NewViewMsg struct {
	Ver int
	View int
	Pubkey string
	VCMsgSet []ViewChangeMsg

	CKpoint int // validator could verify the checkpoint by computing from those Clock components.
	PPMsgSet []PrePrepareMsg
	Clock CommitedLock

	//LtxSet []LeaveTx
	Bloc Block // a config-block for the Leave-tx
	Sig PariSign
}

type PreparedLock struct {
	LockedHeight int
	ThePrePrepare PrePrepareMsg
	LockedHash [32]byte
	LockedQC PrepareQC
}

type CommitedLock struct {
	LockedHeight int
	ThePrePrepare PrePrepareMsg
	LockedHash [32]byte
	LockedQC CommitQC
}

type PrepareQC struct {
	PrepareMsgSet []PrepareMsg
}

type CommitQC struct {
	CommitMsgSet []CommitMsg
}

type CheckPointQC struct {
	Head BlockHead
	QC PrepareQC
}

func NewPreprepareMsg(ver int, view int, order int, pubkeystr string, prvkey *ecdsa.PrivateKey, hashval [32]byte) PrePrepareMsg {
	prepreparemsg := PrePrepareMsg{}
	prepreparemsg.Ver = ver
	prepreparemsg.View = view
	prepreparemsg.Order = order
	prepreparemsg.Digest = hashval

	datatosign := string(prepreparemsg.Ver) + "," + string(prepreparemsg.View) + "," + string(prepreparemsg.Order) + "," + string(hashval[:])
	prepreparemsg.Sig.Sign([]byte(datatosign), prvkey)
	prepreparemsg.Pubkey = pubkeystr
	return prepreparemsg
}

func NewPrepareMsg(ver int, view int, order int, digest [32]byte, pubkeystr string, prvkey *ecdsa.PrivateKey) PrepareMsg {
	preparemsg := PrepareMsg{}
	preparemsg.Ver = ver
	preparemsg.View = view
	preparemsg.Order = order
	preparemsg.Digest = digest

	datatosign := string(preparemsg.Ver) + "," + string(preparemsg.View) + "," + string(preparemsg.Order) + "," + string(preparemsg.Digest[:])
	preparemsg.Sig.Sign([]byte(datatosign), prvkey)
	preparemsg.Pubkey = pubkeystr
	return preparemsg
}

func NewCommitMsg(ver int, view int, order int, digest [32]byte, pubkeystr string, prvkey *ecdsa.PrivateKey) CommitMsg {
	commitmsg := CommitMsg{}
	commitmsg.Ver = ver
	commitmsg.View = view
	commitmsg.Order = order
	commitmsg.Digest = digest

	datatosign := string(commitmsg.Ver) + "," + string(commitmsg.View) + "," + string(commitmsg.Order) + "," + string(commitmsg.Digest[:])
	commitmsg.Sig.Sign([]byte(datatosign), prvkey)
	commitmsg.Pubkey = pubkeystr
	return commitmsg
}

func NewViewChangeMsg(ver int, view int, ltxset []LeaveTx, ckpheigh int, ckpqc CheckPointQC, plock PreparedLock, clock CommitedLock, pubkey string, prvkey *ecdsa.PrivateKey) ViewChangeMsg {
	vcmsg := ViewChangeMsg{}
	vcmsg.Ver = ver
	vcmsg.View = view
	vcmsg.Ckpheight = ckpheigh
	vcmsg.Ckpqc = ckpqc
	vcmsg.Plock = plock
	vcmsg.Clock = clock
	vcmsg.LtxSet = ltxset

	datatosign := sha256.Sum256(vcmsg.Serialize())
	fmt.Println("pubkey: ", pubkey, " signs data ", datatosign)
	vcmsg.Sig.Sign(datatosign[:], prvkey)
	vcmsg.Pubkey = pubkey

	return vcmsg
}

func NewNewViewMsgWithBlock(ver int, view int, pubkey string, vcset []ViewChangeMsg, prvkey *ecdsa.PrivateKey, bloc Block) NewViewMsg {
	nvmsg := NewViewMsg{}

	nvmsg.Ver = ver
	nvmsg.View = view
	nvmsg.VCMsgSet = make([]ViewChangeMsg, len(vcset))
	copy(nvmsg.VCMsgSet, vcset)

	nvmsg.PPMsgSet = []PrePrepareMsg{}
	// first, find the maximum block height
	// then, get the locked hash
	max_s := 0 // the latest checkpoint
	for _, vcmsg := range vcset {
		max_s = Takemax(max_s, vcmsg.Ckpheight)
	}
	nvmsg.CKpoint = max_s
	// find if there exists a commitlock
	for _, vcmsg := range nvmsg.VCMsgSet {
		if max_s == vcmsg.Ckpheight {
			if vcmsg.Clock.LockedHeight == max_s + 1 {
				// believe this is right for some vcmsg, at least the one from leader itself
				nvmsg.Clock = vcmsg.Clock
				break
			}
		}
	}

	if nvmsg.Clock.LockedHeight==0 {
		log.Panic("leader fail when create new-view msg for config-block")
	}

	// construct the new pre-prepare msg for the config-block
	prepremsg := PrePrepareMsg{}
	prepremsg.View = view
	prepremsg.Order = bloc.Blockhead.Height
	prepremsg.Digest = bloc.GetHash()
	predatatosign := string(prepremsg.View) + "," + string(prepremsg.Order) + "," + string(prepremsg.Digest[:])
	prepremsg.Sig.Sign([]byte(predatatosign), prvkey)
	prepremsg.Pubkey = pubkey
	nvmsg.PPMsgSet = append(nvmsg.PPMsgSet, prepremsg)

	nvmsg.Bloc = bloc

	datatosign := sha256.Sum256(nvmsg.Serialize())
	nvmsg.Sig.Sign(datatosign[:], prvkey)
	nvmsg.Pubkey = pubkey

	return nvmsg
}

func NewNewViewMsgWithoutBlock(ver int, view int, pubkey string, vcset []ViewChangeMsg, prvkey *ecdsa.PrivateKey) NewViewMsg {
	// there are two types of new-view msg according to the collected vc-msgs. The first one is there exists at least a vc-msg who contains a commit-lock, in this case,
	// the new-view msg has a commitlock but empty Pre-prepareMsgSet; the second one is all vc-msg with the highest checkpoint has only prepare-lock, in this case,
	// the new-view msg has a 1-length Pre-prepareMsgSet but empty commitlock.
	nvmsg := NewViewMsg{}
	nvmsg.Ver = ver
	nvmsg.View = view
	nvmsg.VCMsgSet = make([]ViewChangeMsg, len(vcset))
	copy(nvmsg.VCMsgSet, vcset)

	// calculate nvmsg.PPMsgSet
	nvmsg.PPMsgSet = []PrePrepareMsg{}
	// first, find the maximum block height
	// then, get the locked hash
	max_s := 0 // the latest checkpoint
	lockedheigh := 0 // height for the locked(prepared) block
	thediges := [32]byte{}
	for _, vcmsg := range vcset {
		max_s = Takemax(max_s, vcmsg.Ckpheight)
	}
	nvmsg.CKpoint = max_s
	// find if there exists a commitlock
	for _, vcmsg := range nvmsg.VCMsgSet {
		if max_s == vcmsg.Ckpheight {
			if vcmsg.Clock.LockedHeight == max_s + 1 {
				nvmsg.Clock = vcmsg.Clock
				break
			}
			lockedheigh = vcmsg.Plock.LockedHeight
			thediges = vcmsg.Plock.LockedHash
		}
	}

	// construct the new pre-prepare msg for the locked hash(block)
	if nvmsg.Clock.LockedHeight==0 {
		prepremsg := PrePrepareMsg{}
		prepremsg.View = view
		prepremsg.Order = lockedheigh
		prepremsg.Digest = thediges
		predatatosign := string(prepremsg.View) + "," + string(prepremsg.Order) + "," + string(prepremsg.Digest[:])
		prepremsg.Sig.Sign([]byte(predatatosign), prvkey)
		prepremsg.Pubkey = pubkey
		nvmsg.PPMsgSet = append(nvmsg.PPMsgSet, prepremsg)
	}

	//// add leave-tx to new-view msg
	//nvmsg.LtxSet = make([]LeaveTx, 0)
	//for _, vcmsg := range nvmsg.VCMsgSet {
	//	if len(vcmsg.LtxSet)>0 {
	//		theltx := vcmsg.LtxSet[0]
	//		nvmsg.LtxSet = append(nvmsg.LtxSet, theltx)
	//		break
	//		// todo, very informal and simple methode, need further polishing up
	//	}
	//}




	datatosign := sha256.Sum256(nvmsg.Serialize())
	nvmsg.Sig.Sign(datatosign[:], prvkey)
	nvmsg.Pubkey = pubkey
	return nvmsg
}

func AddPreparemsg(ppmset *[]PrepareMsg, ppmsg PrepareMsg) {
	needappend := true
	for i:=0; i<len(*ppmset); i++ {
		if (*ppmset)[i].Pubkey==ppmsg.Pubkey {
			(*ppmset)[i] = ppmsg
			needappend = false
			break
		}
	}
	if needappend {
		*ppmset = append(*ppmset, ppmsg)
	}
}

func AddCommitmsg(cmmset *[]CommitMsg, cmmsg CommitMsg) {
	needappend := true
	for i:=0; i<len(*cmmset); i++ {
		if (*cmmset)[i].Pubkey==cmmsg.Pubkey {
			(*cmmset)[i] = cmmsg
			needappend = false
			break
		}
	}
	if needappend {
		*cmmset = append(*cmmset, cmmsg)
	}
}

func AddVcmsg(vcmset *[]ViewChangeMsg, vcmsg ViewChangeMsg) {
	needappend := true
	for i:=0; i<len(*vcmset); i++ {
		if (*vcmset)[i].Pubkey==vcmsg.Pubkey {
			(*vcmset)[i] = vcmsg
			needappend = false
			break
		}
	}
	if needappend {
		*vcmset = append(*vcmset, vcmsg)
	}
}

func (prepreparemsg PrePrepareMsg) Serialize() []byte {
	var encoded bytes.Buffer

	gob.Register(elliptic.P256())
	enc := gob.NewEncoder(&encoded)
	err := enc.Encode(prepreparemsg)
	if err != nil {
		log.Panic(err)
	}

	return encoded.Bytes()
}

func (preparemsg PrepareMsg) Serialize() []byte {
	var encoded bytes.Buffer

	gob.Register(elliptic.P256())
	enc := gob.NewEncoder(&encoded)
	err := enc.Encode(preparemsg)
	if err != nil {
		log.Panic(err)
	}

	return encoded.Bytes()
}

func (commitmsg CommitMsg) Serialize() []byte {
	var encoded bytes.Buffer
	gob.Register(elliptic.P256())
	enc := gob.NewEncoder(&encoded)
	err := enc.Encode(commitmsg)
	if err != nil {
		log.Panic(err)
	}

	return encoded.Bytes()
}

func (vcmsg *ViewChangeMsg) Serialize() []byte {
	var encoded bytes.Buffer
	gob.Register(elliptic.P256())
	enc := gob.NewEncoder(&encoded)
	err := enc.Encode(vcmsg)
	if err != nil {
		log.Panic(err)
	}

	return encoded.Bytes()
}

func (nvmsg NewViewMsg) Serialize() []byte {
	var encoded bytes.Buffer
	gob.Register(elliptic.P256())
	enc := gob.NewEncoder(&encoded)
	err := enc.Encode(nvmsg)
	if err != nil {
		log.Panic(err)
	}

	return encoded.Bytes()
}

func (prepareqc *PrepareQC) Serialize() []byte {
	var encoded bytes.Buffer
	enc := gob.NewEncoder(&encoded)
	err := enc.Encode(*prepareqc)
	if err != nil {
		log.Panic(err)
	}
	return encoded.Bytes()
}

func (prepareqc *PrepareQC) Deserialize(conten []byte) {
	var buff bytes.Buffer
	var theqc PrepareQC
	buff.Write(conten)
	dec := gob.NewDecoder(&buff)
	err := dec.Decode(&theqc)
	if err != nil {
		log.Panic(err)
	}
	prepareqc.PrepareMsgSet = theqc.PrepareMsgSet
}

func (commitqc *CommitQC) Serialize() []byte {
	var encoded bytes.Buffer
	enc := gob.NewEncoder(&encoded)
	err := enc.Encode(*commitqc)
	if err != nil {
		log.Panic(err)
	}
	return encoded.Bytes()
}

func (commitqc *CommitQC) Deserialize(conten []byte) {
	var buff bytes.Buffer
	buff.Write(conten)
	dec := gob.NewDecoder(&buff)
	err := dec.Decode(&commitqc)
	if err != nil {
		fmt.Println("serialized commitqc decoding error")
		log.Panic(err)
	}
}

