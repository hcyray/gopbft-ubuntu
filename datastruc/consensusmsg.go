package datastruc

import (
	"crypto/ecdsa"
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
	SenderId int
	//Ckpheight int
	//Ckpqc CheckPointQC
	Lockheight int
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

	//CKpoint int // validator could verify the checkpoint by computing from those Clock components.
	Lockheight int
	Kind string
	Plock PreparedLock
	Clock CommitedLock
	PPMsgSet []PrePrepareMsg


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

func NewViewChangeMsg(ver int, view int, senderid int, ltxset []LeaveTx, lockheight int, plock PreparedLock, clock CommitedLock, pubkey string, prvkey *ecdsa.PrivateKey) ViewChangeMsg {
	vcmsg := ViewChangeMsg{}
	vcmsg.Ver = ver
	vcmsg.View = view
	vcmsg.SenderId = senderid
	//vcmsg.Ckpheight = ckpheigh
	//vcmsg.Ckpqc = ckpqc
	vcmsg.Lockheight = lockheight
	vcmsg.Plock = plock
	vcmsg.Clock = clock
	vcmsg.LtxSet = ltxset


	datatosign := string(vcmsg.Ver) + "," + string(vcmsg.View) + "," + string(vcmsg.SenderId) + "," +string(vcmsg.Lockheight)
	vcmsg.Sig.Sign([]byte(datatosign), prvkey)
	vcmsg.Pubkey = pubkey

	return vcmsg
}

func NewNewViewMsgWithBlock(ver int, view int, pubkey string, vcset []ViewChangeMsg, prvkey *ecdsa.PrivateKey, bloc Block) NewViewMsg {
	nvmsg := NewViewMsg{}

	nvmsg.Ver = ver
	nvmsg.View = view
	nvmsg.VCMsgSet = make([]ViewChangeMsg, len(vcset))
	copy(nvmsg.VCMsgSet, vcset)

	lockedheigh := 0 // height for the locked(prepared) block
	kind := "n"
	var plock PreparedLock
	var clock CommitedLock
	thediges := [32]byte{}
	// first find maximum lockheight in all view-change msg
	for _, vcmsg := range vcset {
		lockedheigh = Takemax(lockedheigh, vcmsg.Lockheight)
	}
	for _, vcmsg := range nvmsg.VCMsgSet {
		if lockedheigh == vcmsg.Lockheight {
			if vcmsg.Clock.LockedHeight>0 {
				clock = vcmsg.Clock
				kind = "c"
				break
			} else {
				plock = vcmsg.Plock
				kind = "p"
				thediges = vcmsg.Plock.LockedHash
			}
		}
	}

	nvmsg.Kind = kind
	nvmsg.Lockheight = lockedheigh
	nvmsg.Plock = plock
	nvmsg.Clock = clock

	if nvmsg.Kind=="p" {
		log.Panic("leader fail when create new-view msg for config-block, it needs to repropose", thediges)
	}

	// construct the new pre-prepare msg for the config-block
	nvmsg.PPMsgSet = []PrePrepareMsg{}
	prepremsg := PrePrepareMsg{}
	prepremsg.View = view
	prepremsg.Order = bloc.Blockhead.Height
	prepremsg.Digest = bloc.GetHash()
	predatatosign := string(prepremsg.View) + "," + string(prepremsg.Order) + "," + string(prepremsg.Digest[:])
	prepremsg.Sig.Sign([]byte(predatatosign), prvkey)
	prepremsg.Pubkey = pubkey
	nvmsg.PPMsgSet = append(nvmsg.PPMsgSet, prepremsg)

	nvmsg.Bloc = bloc

	datatosign := "newviewmsg," + string(nvmsg.Ver) + "," + string(nvmsg.View)
	nvmsg.Sig.Sign([]byte(datatosign), prvkey)
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


	lockedheigh := 0 // height for the locked(prepared) block
	kind := "n"
	var plock PreparedLock
	var clock CommitedLock
	thediges := [32]byte{}
	// first find maximum lockheight in all view-change msg
	for _, vcmsg := range vcset {
		lockedheigh = Takemax(lockedheigh, vcmsg.Lockheight)
	}
	for _, vcmsg := range nvmsg.VCMsgSet {
		if lockedheigh == vcmsg.Lockheight {
			if vcmsg.Clock.LockedHeight>0 {
				clock = vcmsg.Clock
				kind = "c"
				break
			} else {
				plock = vcmsg.Plock
				kind = "p"
				thediges = vcmsg.Plock.LockedHash
			}
		}
	}

	nvmsg.Kind = kind
	nvmsg.Lockheight = lockedheigh
	nvmsg.Plock = plock
	nvmsg.Clock = clock

	// construct the new pre-prepare msg for the locked hash(block)
	nvmsg.PPMsgSet = []PrePrepareMsg{}
	if nvmsg.Kind=="p" {
		prepremsg := PrePrepareMsg{}
		prepremsg.View = view
		prepremsg.Order = lockedheigh
		prepremsg.Digest = thediges
		predatatosign := string(prepremsg.View) + "," + string(prepremsg.Order) + "," + string(prepremsg.Digest[:])
		prepremsg.Sig.Sign([]byte(predatatosign), prvkey)
		prepremsg.Pubkey = pubkey
		nvmsg.PPMsgSet = append(nvmsg.PPMsgSet, prepremsg)
	}


	datatosign := "newviewmsg," + string(nvmsg.Ver) + "," + string(nvmsg.View)
	nvmsg.Sig.Sign([]byte(datatosign), prvkey)
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
