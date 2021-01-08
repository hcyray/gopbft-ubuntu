package pbft

const ConsensusTimer = 4000
const InauguratTimer = 1000
const MonitorTimer = 1000
const ScanInterval = 2
const ThreadExit = 5
const LeaderLease = 5
const JOININGTHRES = 1000

const BlockVolume = 1024
const CheckPointInterv = 10


const (
	stat_consensus = iota
	stat_inaugurate
	stat_viewchange
	Unstarted
	Preprepared
	Prepared
	Commited
)