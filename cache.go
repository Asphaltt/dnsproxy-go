package dnsproxy

import (
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Record is a cached record,
// Expired is the expire timestamp,
// Msg is the dns message.
type Record struct {
	Expired time.Time
	Msg     *dns.Msg
}

// NewRecord creates a new record from msg.
func NewRecord(msg *dns.Msg) (*Record, bool) {
	if len(msg.Answer) == 0 {
		return nil, false
	}

	ttl := time.Duration(msg.Answer[0].Header().Ttl) * time.Second
	return &Record{
		Expired: time.Now().Add(ttl),
		Msg:     msg,
	}, true
}

// IsExpired gets whether the record has been expired.
func (r *Record) IsExpired() bool {
	return time.Now().After(r.Expired)
}

const (
	maxLen  = 255
	initCap = 28 * 2 // 26 letters with '.' and '_'
)

// Trie is a standard trie tree for dns.
type Trie struct {
	sync.RWMutex
	IsLeaf bool
	Next   map[rune]*Trie
	Data   interface{}
}

// NewTrie creates a new trie.
func NewTrie() *Trie {
	return &Trie{
		Next: make(map[rune]*Trie, initCap),
	}
}

// Add adds a record to the trie.
func (t *Trie) Add(name string, r *Record) {
	t.Insert(name, r)
}

// Insert inserts data to the trie.
func (t *Trie) Insert(name string, data interface{}) {
	t.Lock()

	word, node := reverseString(name), t

	for _, c := range word {
		if node.Next[c] == nil {
			node.Next[c] = NewTrie()
		}
		node = node.Next[c]
	}

	node.IsLeaf = true
	node.Data = data

	t.Unlock()
}

// Delete deletes the data whose key is name.
func (t *Trie) Delete(name string) {
	t.Lock()
	t.remove(name)
	t.Unlock()
}

func (t *Trie) remove(name string) {
	word, node := reverseString(name), t

	found := true // not have Data which you want to delete
	for _, c := range word {
		if node.Next[c] == nil { // not found
			found = false
			break
		}
		node = node.Next[c]
	}

	if found && node.IsLeaf {
		node.Data = nil
	}
}

// Get gets a record from trie whose key is name.
// Delete the record, if the record has been expired.
func (t *Trie) Get(name string) (*Record, bool) {
	t.Lock()
	defer t.Unlock()

	v, ok := t.find(name)
	if !ok {
		return nil, false
	}
	r, ok := v.(*Record)
	if !ok {
		return nil, false
	}
	if r.IsExpired() {
		t.remove(name)
		return nil, false
	}

	// update ttl
	ttl := uint32(r.Expired.Sub(time.Now()))
	updateTTLOf(r.Msg.Answer, ttl)
	updateTTLOf(r.Msg.Ns, ttl)
	updateTTLOf(r.Msg.Extra, ttl)
	return r, true
}

func updateTTLOf(rrs []dns.RR, ttl uint32) {
	if len(rrs) == 0 {
		return
	}
	for i := range rrs {
		h := rrs[i].Header()
		h.Ttl = ttl
	}
}

// Find finds the data of the key `name`
func (t *Trie) Find(name string) (val interface{}, ok bool) {
	t.RLock()
	val, ok = t.find(name)
	t.RUnlock()
	return
}

func (t *Trie) find(name string) (interface{}, bool) {

	word, node := reverseString(name), t

	for _, c := range word {
		if node.Next[c] == nil {
			return nil, false
		}

		node = node.Next[c]
	}

	if node.IsLeaf {
		return node.Data, true
	}

	return nil, false
}

func reverseString(s string) string {
	r := []rune(s)
	for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}
