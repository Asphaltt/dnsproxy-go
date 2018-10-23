package dnsproxy

import (
	"io"
	"net"
	"time"

	"github.com/miekg/dns"
)

// Config is the config about the dnsproxy
type Config struct {
	// address to listen on
	Addr string

	// up dns servers to proxy
	UpServers []string

	// proxy with dns cache
	WithCache bool
	CacheFile string

	// worker pool size
	WorkerPoolMin, WorkerPoolMax int
}

func (cfg *Config) check() {
	if cfg.WorkerPoolMin < 1 {
		cfg.WorkerPoolMin = 1
	}
	if cfg.WorkerPoolMax < cfg.WorkerPoolMin {
		cfg.WorkerPoolMax = cfg.WorkerPoolMin + 10
	}
}

type server struct {
	lconn    *net.UDPConn
	config   *Config
	pool     *workerPool
	recvChan chan *userPacket
	sendChan chan *userPacket

	cache     *Trie
	cacheChan chan *dns.Msg
}

var defaultServer *server

// Start starts to run dnsproxy-server.
func Start(cfg *Config) error {
	laddr, err := net.ResolveUDPAddr("udp", cfg.Addr)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return err
	}

	cfg.check()
	s := &server{
		lconn:    conn,
		config:   cfg,
		recvChan: make(chan *userPacket, cfg.WorkerPoolMax),
		sendChan: make(chan *userPacket, cfg.WorkerPoolMax),
	}
	s.pool = newWorkerPool(s)

	if cfg.WithCache {
		s.cache = NewTrie()
		s.cacheChan = make(chan *dns.Msg, cfg.WorkerPoolMax)
		go s.cacheMsg()
	}

	go s.response()
	go s.run()

	defaultServer = s
	return nil
}

// Close closes the running dnsproxy
func Close() error {
	if defaultServer != nil {
		defaultServer.close()
	}
	return nil
}

func (s *server) run() {
	for {
		data := make([]byte, 512)
		s.lconn.SetDeadline(time.Now().Add(time.Second))
		n, raddr, err := s.lconn.ReadFromUDP(data)
		if err == io.EOF {
			return
		}
		if err != nil || raddr == nil {
			continue
		}
		s.recv(data[:n], raddr)
	}
}

func (s *server) recv(data []byte, raddr *net.UDPAddr) {
	s.recvChan <- &userPacket{data: data, addr: raddr}
	if len(s.recvChan) > s.config.WorkerPoolMin {
		s.pool.openOne()
	} else if len(s.recvChan) < s.config.WorkerPoolMin {
		s.pool.closeOne()
	}
}

func (s *server) response() {
	for {
		p, ok := <-s.sendChan
		if !ok {
			return
		}
		s.lconn.WriteToUDP(p.data, p.addr)
	}
}

func (s *server) close() {
	s.lconn.Close()
	s.pool.close()
}

func (s *server) toCache(msg *dns.Msg) {
	s.cacheChan <- msg
}
func (s *server) cacheMsg() {
	for {
		msg, ok := <-s.cacheChan
		if !ok {
			return
		}
		r, ok := NewRecord(msg)
		if ok {
			s.cache.Add(getQuetion(msg), r)
		}
	}
}
