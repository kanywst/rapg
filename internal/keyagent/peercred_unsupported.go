//go:build !linux && !darwin

package keyagent

import (
	"errors"
	"net"
)

// ErrUnsupportedPlatform reports that this OS has no peer-credential check
// wired up, so the agent refuses to run at all.
//
// rapg ships a Windows build, and Windows has no unix sockets. Named pipes
// with a SID check are the equivalent and nobody has asked for them yet.
// Failing loudly is the point: an agent that listened without being able to
// identify its peers would be a weaker mechanism wearing the same name.
var ErrUnsupportedPlatform = errors.New("keyagent: not supported on this platform")

func peerUID(_ *net.UnixConn) (uint32, error) {
	return 0, ErrUnsupportedPlatform
}
