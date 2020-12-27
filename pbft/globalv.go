package pbft

const ConsensusTimer = 4000
const InauguratTimer = 4000
const MonitorTimer = 1000
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