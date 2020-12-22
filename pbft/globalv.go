package pbft

const ConsensusTimer = 2000
const InauguratTimer = 2000
const ScanInterval = 2
const ThreadExit = 5
const LeaderLease = 10

const BlockVolume = 512

const (
	stat_consensus = iota
	stat_inaugurate
	stat_viewchange
	Unstarted
	Preprepared
	Prepared
	Commited
)