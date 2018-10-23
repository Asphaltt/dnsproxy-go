package dnsproxy

import (
	"math/rand"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// IsSuccessfulResponse gets whether the msg is a successful response
func IsSuccessfulResponse(msg *dns.Msg) bool {
	return msg.Rcode == dns.RcodeSuccess
}

// IsEmptyResponse gets whether the msg is an empty response
// which has no answer, no ns and no extra
func IsEmptyResponse(msg *dns.Msg) bool {
	return len(msg.Answer) == 0 && len(msg.Ns) == 0 && len(msg.Extra) == 0
}

// GotAnswer gets whether do get the answer,
// whose RRtype is same as Qtype or
// the NS RR is a SOA
func GotAnswer(msg *dns.Msg) bool {
	for _, an := range msg.Answer {
		if an == nil {
			continue
		}
		if an.Header().Rrtype == msg.Question[0].Qtype {
			// answer type: A, AAAA, TXT, PTR
			return true
		}
	}

	if len(msg.Answer) == 0 && len(msg.Ns) == 1 && msg.Ns[0] != nil &&
		msg.Ns[0].Header().Rrtype == dns.TypeSOA {
		// SOA with no answer
		return true
	}

	return false
}

// FindExtras gets a string array from msg's extra rr
func FindExtras(msg *dns.Msg) []string {
	x := []string{}
	for _, ad := range msg.Extra {
		h := ad.Header()
		if h.Rrtype == dns.TypeA {
			if a, ok := ad.(*dns.A); ok { // assert *A instead of A
				x = append(x, a.A.String())
			}
		}
	}
	return x
}

// FindNS gets a string array from msg's ns rr,
// which has no answer.
func FindNS(msg *dns.Msg) ([]string, bool) {
	if len(msg.Answer) > 0 {
		return nil, false
	}

	ns := make([]string, 0, len(msg.Ns))
	for _, n := range msg.Ns {
		if n.Header().Rrtype == dns.TypeNS {
			if x, ok := n.(*dns.NS); ok {
				ns = append(ns, x.Ns)
			}
		}
	}
	return ns, true
}

// FindNSExtras gets a copied message from msg,
// the copy's answer is msg's extra
func FindNSExtras(msg *dns.Msg) (*dns.Msg, bool) {
	if msg.Authoritative && len(msg.Extra) > 0 {
		_msg := msg.Copy()
		_msg.Answer = make([]dns.RR, len(msg.Extra))
		copy(_msg.Answer, msg.Extra)
		return _msg, true
	}
	return nil, false
}

// FindCname gets the final cname in the msg.
func FindCname(msg *dns.Msg) (string, bool) {
	// msg may has more than one CNAME
	// NOTE: should return only one CNAME
	x := make(map[string]string)
	for _, an := range append(msg.Answer, msg.Ns...) {
		if an == nil || an.Header().Rrtype != dns.TypeCNAME {
			continue
		}
		if cname, ok := an.(*dns.CNAME); ok {
			x[cname.Hdr.Name] = cname.Target
		}
	}
	if len(x) == 0 {
		return "", false
	}
	queryName := msg.Question[0].Name
	for {
		if _, ok := x[queryName]; ok {
			queryName = x[queryName]
		} else {
			return queryName, true
		}
	}
}

// NewQuery creates a new dns query messge
func NewQuery(names []string) *dns.Msg {
	qus := make([]dns.Question, len(names))
	for i, name := range names {
		if strings.HasSuffix(name, "in-addr.arpa.") {
			qus[i] = dns.Question{
				Name:   name,
				Qtype:  dns.TypePTR,
				Qclass: dns.ClassINET,
			}
			continue
		}
		qus[i] = dns.Question{
			Name:   name,
			Qtype:  dns.TypeA,
			Qclass: dns.ClassINET,
		}
	}
	msg := new(dns.Msg)
	msg.Question = qus
	msg.RecursionDesired = true
	rand.Seed(time.Now().Unix())
	msg.Id = uint16(rand.Uint32())
	return msg
}

// NewResponse creates a new dns response message with the gived rcode
func NewResponse(rcode int) *dns.Msg {
	msg := new(dns.Msg)
	msg.Response = true
	msg.RecursionDesired = true
	msg.Rcode = rcode
	return msg
}

func getQuetion(msg *dns.Msg) string {
	return strings.ToLower(dns.TypeToString[msg.Question[0].Qtype]) + "." + msg.Question[0].Name
}
