package pbft

const ConsensusTimer = 2000
const InauguratTimer = 1000
const MonitorTimer = 2000
const ScanInterval = 2
const ThreadExit = 5
const LeaderLease = 5
const JOININGTHRES = 680

const BlockVolume = 1024
const CheckPointInterv = 10

const Phaselen = 30


const (
	stat_consensus = iota
	stat_inaugurate
	stat_viewchange
	Unstarted
	Preprepared
	Prepared
	Commited
)