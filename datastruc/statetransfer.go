package datastruc

import "crypto/ecdsa"

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

	Pubkey string
	Sig PariSign
}

type ReadConfigRequest struct {
	Id int
	IpportAddr string
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

func NewReplyStateTransfer(height int, balance map[string]int, pubkey string, prvkey *ecdsa.PrivateKey) ReplyStateTransMsg {
	replymsg := ReplyStateTransMsg{}
	replymsg.Height = height
	replymsg.AccountBalance = balance
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