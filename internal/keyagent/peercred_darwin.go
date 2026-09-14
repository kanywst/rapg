//go:build darwin

package keyagent

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// peerUID returns the uid of the process on the other end of conn.
//
// The 0700 socket directory already keeps other users out. This is the second
// check: directory modes can be changed, and a bug that loosened them should
// not silently turn into cross-user vault access.
//
// darwin spells this LOCAL_PEERCRED at SOL_LOCAL rather than Linux's
// SO_PEERCRED at SOL_SOCKET, and returns an xucred (no pid) rather than a
// ucred. Only the uid is needed here, so the difference does not leak out of
// this file.
func peerUID(conn *net.UnixConn) (uint32, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}

	var (
		cred    *unix.Xucred
		credErr error
	)
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if credErr != nil {
		return 0, fmt.Errorf("keyagent: LOCAL_PEERCRED: %w", credErr)
	}
	return cred.Uid, nil
}
