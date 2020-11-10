package datastruc

type Datatosend struct {
	Destorder []int
	MsgType string
	Msg []byte
}

type DataReceived struct {
	MsgType string
	Msg []byte
}

type DataMemberChange struct {
	Kind string
	Id int
}

type DatatosendWithIp struct {
	DestIp []string
	MsgType string
	Msg []byte
}