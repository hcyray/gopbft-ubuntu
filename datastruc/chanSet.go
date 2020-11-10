package datastruc

type ChanSet struct {
	sendCh chan Datatosend
	broadCh chan Datatosend
	memberidchangeCh chan DataMemberChange
	censorshipmonitorCh chan [32]byte
	statetransferqueryCh chan QueryStateTransMsg
	statetransferreplyCh chan ReplyStateTransMsg
	cdetestrecvch chan DataReceived
	cderesponserecvch chan DataReceived
}

