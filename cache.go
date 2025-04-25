package pveresolve

import (
	"github.com/coredns/coredns/plugin"
	"github.com/miekg/dns"
	"sync"
)

type Cache struct {
	zs     plugin.Zones
	mA     map[string]dns.RR
	mAAAA  map[string]dns.RR
	mUnkRR map[string]dns.RR
	mx     *sync.RWMutex
}

func NewCache(zs plugin.Zones) *Cache {
	return &Cache{
		zs:     zs,
		mA:     map[string]dns.RR{},
		mAAAA:  map[string]dns.RR{},
		mUnkRR: map[string]dns.RR{},
		mx:     &sync.RWMutex{},
	}
}

func (c *Cache) Zones() plugin.Zones {
	c.mx.RLock()
	defer c.mx.RUnlock()
	return c.zs
}

func (c *Cache) Record(d string, rrtype uint16) (rr dns.RR, ok bool) {
	c.mx.RLock()
	defer c.mx.RUnlock()

	switch rrtype {
	case dns.TypeA:
		rr, ok = c.mA[d]
	case dns.TypeAAAA:
		rr, ok = c.mAAAA[d]
	default:
		rr, ok = c.mUnkRR[d]
	}
	return
}

func (c *Cache) Update(zs plugin.Zones, rs map[string]dns.RR) {
	c.mx.Lock()
	defer c.mx.Unlock()

	c.zs = zs
	for d, r := range rs {
		switch r.Header().Rrtype {
		case dns.TypeA:
			c.mA[d] = r
		case dns.TypeAAAA:
			c.mAAAA[d] = r
		default:
			c.mUnkRR[d] = r
		}
	}
}
