package pveresolve

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/pkg/dnsutil"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/luthermonson/go-proxmox"
	"github.com/miekg/dns"
	"net"
	"net/http"
	"time"
)

type Updater struct {
	pve                *proxmox.Client
	zone               string
	pvePoolAsSubdomain bool
	network            *net.IPNet
	ttl                uint32
	c                  *Cache
	log                clog.P
}

func NewUpdater(cfg Config, c *Cache, log clog.P) (*Updater, error) {
	var authOpt proxmox.Option
	if cfg.PveUsername != "" && cfg.PvePassword != "" {
		authOpt = proxmox.WithCredentials(&proxmox.Credentials{
			Username: cfg.PveUsername,
			Password: cfg.PvePassword,
			Otp:      cfg.PveOTP,
			Realm:    cfg.PveRealm,
		})
	} else if cfg.PveToken != "" && cfg.PveSecret != "" {
		authOpt = proxmox.WithAPIToken(cfg.PveToken, cfg.PveSecret)
	} else {
		return nil, errors.New("No provided Proxmox authentication configuration")
	}

	pve := proxmox.NewClient(cfg.PveEndpoint, authOpt, proxmox.WithHTTPClient(&http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: cfg.PveInsecureSkipVerify,
			},
		},
	}))
	_, err := pve.Version(context.TODO())
	if err != nil {
		return nil, err
	}

	return &Updater{
		pve:                pve,
		zone:               cfg.ZoneFqdn,
		pvePoolAsSubdomain: cfg.PvePoolAsSubdomain,
		network:            cfg.Network,
		ttl:                cfg.TTL,
		c:                  c,
		log:                log,
	}, nil
}

func (u *Updater) LaunchCyclicUpdate(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			u.log.Debugf("Context deadline exceeded or canceled")
			return
		case <-time.After(time.Second * time.Duration(u.ttl)):
		}

		u.update(ctx)
	}
}

func (u *Updater) update(ctx context.Context) {
	rs, err := u.pveClusterResources(ctx)
	if err != nil {
		u.log.Errorf("Error getting cluster resources: %v", err)
		return
	}

	mZs := make(map[string]string)
	mRs := make(map[string]dns.RR)

	mZs[u.zone] = u.zone

	for _, r := range rs {
		if r.Status != "running" {
			u.log.Debugf("Skipping VM %d because status is not running", r.VMID)
			continue
		}

		if r.Name == "" {
			u.log.Debugf("Skipping VM %d because empty name", r.VMID)
			continue
		}
		z := u.zone
		if u.pvePoolAsSubdomain {
			z = dns.CanonicalName(dnsutil.Join(r.Pool, u.zone))

			if _, ok := mZs[z]; !ok {
				mZs[z] = z
			}
		}
		d := dns.CanonicalName(dnsutil.Join(r.Name, z))

		switch r.Type {
		case "qemu":
			ifaces, err := u.pveQemuVMInterfaces(ctx, r.Node, r.VMID)
			if err != nil {
				u.log.Errorf("Error getting VM %d interfaces: %v", r.VMID, err)
				continue
			}

			for _, iface := range ifaces {
				for _, ipaddr := range iface.IPAddresses {
					ipaddrbs := net.ParseIP(ipaddr.IPAddress)
					if !u.network.Contains(ipaddrbs) {
						continue
					}

					switch ipaddr.IPAddressType {
					case "ipv4":
						mRs[d] = &dns.A{
							Hdr: dns.RR_Header{
								Name:     d,
								Rrtype:   dns.TypeA,
								Class:    dns.ClassINET,
								Ttl:      u.ttl,
								Rdlength: 4,
							},
							A: ipaddrbs,
						}
					case "ipv6":
						mRs[d] = &dns.AAAA{
							Hdr: dns.RR_Header{
								Name:     d,
								Rrtype:   dns.TypeAAAA,
								Class:    dns.ClassINET,
								Ttl:      u.ttl,
								Rdlength: 16,
							},
							AAAA: ipaddrbs,
						}
					}
				}
			}
		case "lxc":
			ifaces, err := u.pveLxcVMInterfaces(ctx, r.Node, r.VMID)
			if err != nil {
				u.log.Errorf("Error getting LXC %d interfaces: %v", r.VMID, err)
				continue
			}

			for _, iface := range ifaces {
				if ipaddr4bs, _, err := net.ParseCIDR(iface.Inet); err == nil {
					mRs[d] = &dns.A{
						Hdr: dns.RR_Header{
							Name:     d,
							Rrtype:   dns.TypeA,
							Class:    dns.ClassINET,
							Ttl:      u.ttl,
							Rdlength: 4,
						},
						A: ipaddr4bs,
					}
				} else if ipaddr6bs, _, err := net.ParseCIDR(iface.Inet6); err != nil {
					mRs[d] = &dns.AAAA{
						Hdr: dns.RR_Header{
							Name:     d,
							Rrtype:   dns.TypeAAAA,
							Class:    dns.ClassINET,
							Ttl:      u.ttl,
							Rdlength: 16,
						},
						AAAA: ipaddr6bs,
					}
				}
			}
		default:
			u.log.Debugf("Skipping VM %d because type is not supported", r.VMID)
			continue
		}
	}

	zs := plugin.Zones{}
	for _, z := range mZs {
		zs = append(zs, z)
	}
	u.c.Update(zs, mRs)
	u.log.Info("Cache updated")
}

func (u *Updater) pveClusterResources(ctx context.Context) (rs proxmox.ClusterResources, err error) {
	err = u.pve.Get(ctx, "/cluster/resources?type=vm", &rs)
	return
}

func (u *Updater) pveQemuVMInterfaces(ctx context.Context, node string, vmid uint64) (ifaces []*proxmox.AgentNetworkIface, err error) {
	networks := make(map[string][]*proxmox.AgentNetworkIface)
	err = u.pve.Get(ctx, fmt.Sprintf("/nodes/%s/qemu/%d/agent/network-get-interfaces", node, vmid), &networks)
	if err != nil {
		return
	}
	if result, ok := networks["result"]; ok {
		for _, iface := range result {
			ifaces = append(ifaces, iface)
		}
	}
	return
}

func (u *Updater) pveLxcVMInterfaces(ctx context.Context, node string, vmid uint64) (ifaces proxmox.ContainerInterfaces, err error) {
	err = u.pve.Get(ctx, fmt.Sprintf("/nodes/%s/lxc/%d/interfaces", node, vmid), &ifaces)
	return
}
