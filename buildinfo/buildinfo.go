// Package buildinfo identifies the userv.one fork and its protocol reference.
package buildinfo

const (
	Product        = "uservone-amneziawg"
	UpstreamCommit = "b5928efb6ca19f0153958460c3d141f04abc5c2e"
)

var (
	// Version and Commit are replaced with release values through -ldflags.
	Version = "0.1.0"
	Commit  = "dev"
)
