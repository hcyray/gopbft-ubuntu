package pbft

const ConsensusTimer = 2500
const InauguratTimer = 1000
const MonitorTimer = 500
const ScanInterval = 2
const ThreadExit = 5
const LeaderLease = 10
const JOININGTHRES = 1000

const BlockVolume = 2048


const (
	stat_consensus = iota
	stat_inaugurate
	stat_viewchange
	Unstarted
	Preprepared
	Prepared
	Commited
)