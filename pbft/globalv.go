package pbft

const ConsensusTimer = 2000
const InauguratTimer = 2000
const MonitorTimer = 1000
const ScanInterval = 2
const ThreadExit = 5
const LeaderLease = 10
const JOININGTHRES = 400

const BlockVolume = 1028


const (
	stat_consensus = iota
	stat_inaugurate
	stat_viewchange
	Unstarted
	Preprepared
	Prepared
	Commited
)