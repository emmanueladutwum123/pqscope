package measure

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// ASN is an autonomous system: who announces the address a server answered
// on, which identifies the hosting provider or CDN.
type ASN struct {
	Number      int
	Description string // as the table gives it, such as "AKAMAI-AS - Akamai Technologies, Inc."
}

type asnRange struct {
	start, end netip.Addr
	asn        ASN
}

// ASNTable maps addresses to ASNs, from iptoasn.com's ip2asn-combined.tsv
// (public domain, PDDL): start, end, AS number, country, description.
type ASNTable struct {
	ranges []asnRange
}

// LoadASN reads the table, gzipped or not. Rows with AS number 0 ("Not
// routed") are kept, so an unrouted address reports as such.
func LoadASN(r io.Reader) (*ASNTable, error) {
	br := bufio.NewReader(r)
	if magic, err := br.Peek(2); err == nil && magic[0] == 0x1f && magic[1] == 0x8b {
		zr, err := gzip.NewReader(br)
		if err != nil {
			return nil, err
		}
		defer func() { _ = zr.Close() }()
		br = bufio.NewReader(zr)
	}
	t := &ASNTable{}
	sc := bufio.NewScanner(br)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for n := 1; sc.Scan(); n++ {
		f := strings.Split(sc.Text(), "\t")
		if len(f) < 5 {
			return nil, fmt.Errorf("asn line %d: %d fields", n, len(f))
		}
		start, err1 := netip.ParseAddr(f[0])
		end, err2 := netip.ParseAddr(f[1])
		num, err3 := strconv.Atoi(f[2])
		if err1 != nil || err2 != nil || err3 != nil || start.Is4() != end.Is4() || end.Less(start) {
			return nil, fmt.Errorf("asn line %d: bad range %q-%q AS %q", n, f[0], f[1], f[2])
		}
		t.ranges = append(t.ranges, asnRange{start, end, ASN{num, f[4]}})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(t.ranges) == 0 {
		return nil, fmt.Errorf("asn: empty table")
	}
	sort.Slice(t.ranges, func(i, j int) bool { return t.ranges[i].start.Less(t.ranges[j].start) })
	return t, nil
}

// Lookup returns the ASN announcing addr. ok is false when no range holds it.
func (t *ASNTable) Lookup(addr netip.Addr) (ASN, bool) {
	addr = addr.Unmap()
	// The last range starting at or before addr.
	i := sort.Search(len(t.ranges), func(i int) bool { return addr.Less(t.ranges[i].start) }) - 1
	if i < 0 {
		return ASN{}, false
	}
	r := t.ranges[i]
	if r.start.Is4() != addr.Is4() || r.end.Less(addr) {
		return ASN{}, false
	}
	return r.asn, true
}
