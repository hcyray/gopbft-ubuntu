package datastruc

import "crypto/ecdsa"

type CheckPointMsg struct {
	Id int
	Height int
	Syshash [32]byte
	Pubkey string
	Sig PariSign
}

type ConfirmedBlock struct {
	PreppMsg PrePrepareMsg
	Bloc Block
	CommiQC CommitQC
	Cdedelaydata CDEPureDelayData
}

type QueryStateTransMsg struct {
	Id int
	Height int
	Pubkey string
	Sig PariSign
}

type ReplyStateTransMsg struct {

	Height int
	AccountBalance map[string]int
	CheckPointHeight int
	BlockList []Block

	Pubkey string
	Sig PariSign
}

type ReadConfigRequest struct {
	Id int
	IpportAddr string
}

type ReadConfigReply struct {
	Config []PeerIdentity
}

func NewCheckPointMsg(id int, h int, syshash [32]byte, pubk string) CheckPointMsg {
	cpm := CheckPointMsg{}
	cpm.Id = id
	cpm.Height = h
	cpm.Syshash = syshash
	cpm.Pubkey = pubk
	// todo, add sig
	return cpm
}

func NewQueryStateTransfer(id int, height int, pubkey string, prvkey *ecdsa.PrivateKey) QueryStateTransMsg {
	qstmsg := QueryStateTransMsg{}
	qstmsg.Id = id
	qstmsg.Height = height
	datatosign := "queryforstatetransfer" + string(height)

	qstmsg.Pubkey = pubkey
	qstmsg.Sig.Sign([]byte(datatosign), prvkey)
	return qstmsg
}

func NewReplyStateTransfer(height int, ckpheight int, balance map[string]int, blocklist []Block, pubkey string, prvkey *ecdsa.PrivateKey) ReplyStateTransMsg {
	replymsg := ReplyStateTransMsg{}
	replymsg.Height = height
	replymsg.CheckPointHeight = ckpheight
	replymsg.AccountBalance = balance
	replymsg.BlockList = blocklist
	datatosign := "replyforstatetransfer" + string(height)

	replymsg.Pubkey = pubkey
	replymsg.Sig.Sign([]byte(datatosign), prvkey)
	return replymsg
}

func NewReadConfigRequest(id int, ip string) ReadConfigRequest {
	rcr := ReadConfigRequest{}
	rcr.Id = id
	rcr.IpportAddr = ip
	return rcr
}