package dnsproxy

import (
	"encoding/binary"
	"io"
	"net"
	"time"

	"github.com/miekg/dns"
)

const (
	cnameLimit = 7 // prevent cyclic CNAME
	iterLimit  = 7 // prevent too deep iterative resolving

	timeout = time.Second * 10 // timeout for current query
	wait    = time.Second * 2  // timeout for per query with up server
)

var (
	upDNS = []string{"8.8.8.8"}
)

type iresolver interface {
	resolve(*dns.Msg) (*dns.Msg, error)
	close()
}

type resolver struct {
	worker  *worker
	conns   []*net.UDPConn
	servers []string

	ts time.Time
}

type recursiveResolver struct {
	*resolver

	iter *iterativeResolver
}
type iterativeResolver struct {
	*resolver

	servers []string

	cnames, iters    int
	isStandard, isNS bool

	raw, msg *dns.Msg
}

func newResolver(w *worker, upServers []string) iresolver {
	r := &resolver{
		worker:  w,
		servers: upServers,
		ts:      time.Now(),
	}
	if len(upServers) == 0 {
		upServers = upDNS
	} else if len(upServers) > 3 {
		upServers = upServers[:3]
	}
	for _, s := range upServers {
		addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(s, "53"))
		if err != nil {
			continue
		}
		conn, err := net.DialUDP("udp", nil, addr)
		if err != nil {
			continue
		}
		r.conns = append(r.conns, conn)
	}
	return &recursiveResolver{resolver: r}
}

func (r *resolver) close() {
	for _, conn := range r.conns {
		if conn != nil {
			conn.Close()
		}
	}
}

func (r *resolver) isTimeout() bool {
	return time.Since(r.ts) > timeout
}

func (r *resolver) resolve(msg *dns.Msg) (*dns.Msg, error) {
	data, err := msg.Pack()
	if err != nil {
		return nil, err
	}
	// resolve with default up servers
	return r.resolving(data, "", r.do)
}

func (r *resolver) resolveWithServers(msg *dns.Msg, servers []string) (*dns.Msg, error) {
	data, err := msg.Pack()
	if err != nil {
		return nil, err
	}

	for _, s := range servers {
		// resolve with up UDP server
		_msg, err := r.resolving(data, s, r.doWithUDP)
		if err == nil {
			return _msg, nil
		}

		if err == dns.ErrTruncated {
			// resolve with up TCP server
			_msg, err = r.resolving(data, s, r.doWithTCP)
			if err == nil {
				return _msg, nil
			}
		}
	}
	return nil, ErrNotFound
}

func (rr *recursiveResolver) resolve(msg *dns.Msg) (*dns.Msg, error) {
	_msg, err := rr.resolver.resolve(msg)
	if err != nil {
		return nil, ErrServerFailed
	}

	if GotAnswer(_msg) {
		// cache the A/AAAA/CNAME RRs
		if rr.worker.withCache {
			rr.worker.server.toCache(_msg.Copy())
		}
		return _msg, nil
	}

	// do iterative resolving
	rr.iter = &iterativeResolver{resolver: rr.resolver, raw: msg, msg: msg}
	return rr.iter.resolve(_msg)
}

func (ir *iterativeResolver) isExceededTimes() bool {
	ir.iters++
	return ir.iters > iterLimit
}

func (ir *iterativeResolver) isExceededCnames() bool {
	ir.cnames++
	return ir.cnames == cnameLimit
}

func (ir *iterativeResolver) resolve(msg *dns.Msg) (*dns.Msg, error) {
	if ir.isExceededTimes() {
		return nil, ErrServerFailed
	}

	if ir.isTimeout() {
		return nil, ErrServerFailed
	}

	if ir.raw.Id != msg.Id {
		return nil, ErrInvalidResponse
	}

	if GotAnswer(msg) {
		// cache A/AAAA/CNAME RRs
		if ir.worker.withCache {
			ir.worker.server.toCache(msg.Copy())
		}
		return msg, nil
	}

	if ir.isNS {
		if _m, found := FindNSExtras(msg); found {
			return _m, nil
		}
	}

	if len(ir.servers) == 0 {
		ir.servers = upDNS
	}

	// CNAME in Answer with/without NS in Authority with/without A in Additional
	if cname, ok := FindCname(msg); ok {
		// resolve CNAME
		return ir.cname(msg, []string{cname}, ir.servers)
	}

	// TODO(huayra): check duplicate up servers

	if len(ir.servers) == 0 {
		// if it's not standard query, do standard query
		if !ir.isStandard {
			ir.isStandard = true
			ir.servers = upDNS
			return ir.resolve(ir.raw)
		}
		return nil, ErrServerFailed
	}

	m, e := ir.resolver.resolveWithServers(msg, ir.servers)
	if e != nil {
		if !ir.isStandard {
			ir.servers = upDNS
			ir.isStandard = true
			return ir.resolve(msg)
		}
		return nil, ErrServerFailed
	}

	ir.msg = msg
	ir.isStandard = false
	ir.isNS = false
	return ir.resolve(m)
}

func (ir *iterativeResolver) cname(msg *dns.Msg, names, servers []string) (*dns.Msg, error) {
	if ir.isExceededCnames() {
		// prevent cyclic CNAME
		return nil, ErrCyclicCNAME
	}

	// keep the original info
	xid := msg.Id
	questions := msg.Question
	answers := msg.Answer

	// build a new standard DNS query
	ir.msg = msg

	ir.servers = servers
	if len(servers) == 0 {
		ir.servers = upDNS
		ir.isStandard = true
	}
	_msg, err := ir.resolve(msg)
	if err != nil {
		return nil, err
	}

	// reset the important info
	_msg.Id = xid
	_msg.Question = questions
	_msg.Answer = append(_msg.Answer, answers...)
	return _msg, nil
}

type resolvingHandleFunc func(string, []byte, []byte) ([]byte, error)

func (r *resolver) resolving(data []byte, server string, handle resolvingHandleFunc) (*dns.Msg, error) {
	pckSize := 512
	recv := make([]byte, pckSize) // mostly, response is less than 512
	var err error
	for {
		recv, err = handle(server, data, recv)
		if err != nil {
			break
		}
		msg := &dns.Msg{}
		err = msg.Unpack(recv)
		if err == nil {
			// got the message
			return msg, nil
		}

		if err == dns.ErrBuf { // buffer is too small
			if pckSize == 4096 {
				err = ErrHugePacket
				break
			}
			pckSize *= 2
			recv = make([]byte, pckSize) // to receive a huge response
			continue
		}
		break
	}

	if err == dns.ErrTruncated {
		msg := &dns.Msg{}
		recvData := make([]byte, 1<<12) // 4096
		for i := range r.servers {
			recv, err = r.doWithTCP(r.servers[i], data, recvData)
			if err != nil {
				continue
			}
			err = msg.Unpack(recv)
			if err == nil {
				return msg, nil
			}
		}
		return nil, err
	}

	if err != nil {
	} else {
		err = ErrServerFailed
	}
	return nil, err
}

func (r *resolver) do(_ string, data, recv []byte) ([]byte, error) {
	for _, conn := range r.conns {
		conn.SetDeadline(time.Now().Add(wait))
		if _, err := conn.Write(data); err != nil {
			continue
		}
		n, err := conn.Read(recv)
		if err != nil {
			continue
		}
		return recv[:n], nil
	}
	return recv, ErrNotFound
}

func (r *resolver) doWithUDP(s string, data, rcv []byte) ([]byte, error) {
	raddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(s, "53"))
	if err != nil {
		return rcv, err
	}
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return rcv, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(wait)) // 2 second timeout
	if _, err = conn.Write(data); err != nil {
		return rcv, err
	}
	n, err := conn.Read(rcv)
	return rcv[:n], err
}

func (r *resolver) doWithTCP(s string, data, rcv []byte) ([]byte, error) {
	raddr, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(s, "53"))
	if err != nil {
		return rcv, err
	}
	conn, err := net.DialTCP("tcp", nil, raddr)
	if err != nil {
		return rcv, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(wait)) // 2 second timeout
	_data := make([]byte, len(data)+2)
	binary.BigEndian.PutUint16(_data[:2], uint16(len(data)))
	copy(_data[2:], data)
	if _, err = conn.Write(_data); err != nil {
		return rcv, err
	}
	header := []byte{0, 0}
	_, err = io.ReadFull(conn, header)
	if err != nil {
		return rcv, err
	}
	rcv = make([]byte, binary.BigEndian.Uint16(header))
	n, err := conn.Read(rcv)
	return rcv[:n], err
}
