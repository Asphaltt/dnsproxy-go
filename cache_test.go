package dnsproxy

import "testing"

func TestTrie(t *testing.T) {
	trie := NewTrie()

	testTrie(trie, "www.baidu.com", "baidu", t)
	testTrie(trie, "www.google.com.hk", "google", t)
	testTrie(trie, "www.baidu.com", "百度", t)

	if v, ok := trie.Find("www"); ok || v != nil {
		t.Logf("Get invalid value: %v for key: %s, expected value: nil", v, "www")
		t.Fail()
	}
}

func testTrie(trie *Trie, key, val string, t *testing.T) {
	trie.Insert(key, val)
	if v, ok := trie.Find(key); !ok || v != val {
		t.Logf("Get invalid value: %v for key: %s, expected value: %s", v, key, val)
		t.Fail()
	}
}
