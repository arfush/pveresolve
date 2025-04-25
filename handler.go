package pveresolve

import (
	"context"
	"github.com/coredns/coredns/plugin"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
)

type Handler struct {
	Next plugin.Handler

	c   *Cache
	log clog.P
}

func NewHandler(c *Cache, log clog.P) *Handler {
	return &Handler{
		c:   c,
		log: log,
	}
}

func (h *Handler) Name() string {
	return "pveresolve"
}

func (h *Handler) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}
	qname := state.Name()

	if h.c.Zones().Matches(qname) == "" {
		return plugin.NextOrFailure(h.Name(), h.Next, ctx, w, r)
	}

	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	rr, ok := h.c.Record(qname, state.QType())
	if !ok {
		return dns.RcodeNameError, nil
	}
	m.Answer = append(m.Answer, rr)

	err := w.WriteMsg(m)
	if err != nil {
		return dns.RcodeServerFailure, err
	}
	return dns.RcodeSuccess, nil
}
