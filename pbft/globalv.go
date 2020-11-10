package pbft

const ConsensusTimer = 2000
const InauguratTimer = 1000
const ScanInterval = 2
const ThreadExit = 4
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