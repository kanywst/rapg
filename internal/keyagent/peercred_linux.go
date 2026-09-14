//go:build linux

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
func peerUID(conn *net.UnixConn) (uint32, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}

	var (
		cred    *unix.Ucred
		credErr error
	)
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if credErr != nil {
		return 0, fmt.Errorf("keyagent: SO_PEERCRED: %w", credErr)
	}
	return cred.Uid, nil
}
