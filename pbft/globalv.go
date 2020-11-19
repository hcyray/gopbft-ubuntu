package pbft

const ConsensusTimer = 5000
const InauguratTimer = 5000
const ScanInterval = 2
const ThreadExit = 5
const LeaderLease = 7

const BlockVolume = 1024

const (
	stat_consensus = iota
	stat_inaugurate
	stat_viewchange
	Unstarted
	Preprepared
	Prepared
	Commited
)