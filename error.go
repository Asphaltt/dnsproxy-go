package dnsproxy

import "errors"

// predefined errors
var (
	ErrNotFound        = errors.New("Not Found")
	ErrServerFailed    = errors.New("Server Failed")
	ErrInvalidResponse = errors.New("Invalid Response")
	ErrUnexpectedResp  = errors.New("Unexpected Response")
	ErrHugePacket      = errors.New("Huge Packet")
	ErrCyclicCNAME     = errors.New("Maybe cyclic CNAME")
)
