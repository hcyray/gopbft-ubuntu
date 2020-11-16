package pbft

const ConsensusTimer = 5000
const InauguratTimer = 5000
const ScanInterval = 10
const ThreadExit = 5
const LeaderLease = 10

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