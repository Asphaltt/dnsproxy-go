package dnsproxy

import (
	"net"

	"github.com/Asphaltt/hqu"
	"github.com/miekg/dns"
)

type userPacket struct {
	data []byte
	addr *net.UDPAddr
}

type worker struct {
	server *server

	withCache bool

	recvChan chan *userPacket
	sendChan chan *userPacket

	resolver iresolver
}

func newWorker(s *server) *worker {
	w := &worker{
		server:    s,
		withCache: s.config.WithCache,
		recvChan:  s.recvChan,
		sendChan:  s.sendChan,
	}
	w.resolver = newResolver(w, s.config.UpServers)
	go w.run()
	return w
}

func (w *worker) run() {
	for {
		upack, ok := <-w.recvChan
		if !ok {
			return
		}

		msg := new(dns.Msg)
		err := msg.Unpack(upack.data)
		if err != nil {
			continue
		}

		if len(msg.Question) == 0 {
			continue
		}

		// cached resolve
		if w.withCache {
			_msg, ok := w.resolveCache(msg)
			if ok {
				w.send(upack, _msg)
				continue
			}
		}

		// normally resolve
		_msg, err := w.resolver.resolve(msg)
		if err == nil {
			w.send(upack, _msg)
			continue
		}

		w.send(upack, msg)
	}
}

func (w *worker) send(pkt *userPacket, msg *dns.Msg) {
	msg.Response = true
	msg.Rcode = dns.RcodeSuccess
	if len(msg.Answer) == 0 {
		msg.Rcode = dns.RcodeNameError
	}
	msg.RecursionAvailable = true
	var err error
	if pkt.data, err = msg.Pack(); err != nil {
		return
	}
	w.sendChan <- pkt
}

func (w *worker) resolveCache(msg *dns.Msg) (*dns.Msg, bool) {
	r, ok := w.server.cache.Get(getQuetion(msg))
	if !ok {
		return msg, false
	}
	msg.Answer = make([]dns.RR, len(r.Msg.Answer))
	copy(msg.Answer, r.Msg.Answer)
	return msg, len(msg.Answer) > 0
}

func (w *worker) close() {
	w.resolver.close()
}

// -- worker pool

type workerPool struct {
	server  *server
	workers *hqu.Stack

	min, max int
}

func newWorkerPool(s *server) *workerPool {
	p := &workerPool{
		server:  s,
		workers: &hqu.Stack{},
		min:     s.config.WorkerPoolMin,
		max:     s.config.WorkerPoolMax,
	}
	for i := 0; i < s.config.WorkerPoolMin; i++ {
		p.workers.Push(newWorker(s))
	}
	return p
}

func (wp *workerPool) openOne() {
	if wp.size() < wp.max {
		wp.workers.Push(newWorker(wp.server))
	}
}

func (wp *workerPool) closeOne() {
	if wp.size() > wp.min {
		w, _ := wp.workers.Pop()
		if w != nil {
			w.(*worker).close()
		}
	}
}

func (wp *workerPool) size() int {
	return wp.workers.Size()
}

func (wp *workerPool) close() {
	wp.workers.Range(func(v interface{}) bool {
		if v != nil {
			v.(*worker).close()
		}
		return true
	})
}
