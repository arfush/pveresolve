package pveresolve

import (
	"context"
	"fmt"
	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/miekg/dns"
	"net"
	"os"
	"strconv"
)

func init() {
	plugin.Register("pveresolve", setup)
}

func setup(c *caddy.Controller) error {
	log := clog.NewWithPlugin("pveresolve")

	cfgs, err := parse(c)
	if err != nil {
		return err
	}

	for _, cfg := range cfgs {
		ctx, cancel := context.WithCancel(context.Background())
		c.OnShutdown(func() error {
			cancel()
			return nil
		})

		cache := NewCache(plugin.Zones{cfg.ZoneFqdn})

		u, err := NewUpdater(cfg, cache, log)
		if err != nil {
			return err
		}
		c.OnStartup(func() error {
			go u.LaunchCyclicUpdate(ctx)
			return nil
		})

		h := NewHandler(cache, log)
		dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
			h.Next = next
			return h
		})
	}

	return nil
}

func parse(c *caddy.Controller) (cfgs []Config, err error) {
	for c.Next() {
		args := c.RemainingArgs()
		if len(args) != 1 {
			return nil, fmt.Errorf("Incorrect number of arguments at %d line. Expected 1, got %d", c.Line(), len(args))
		}

		cfg := Config{
			ZoneFqdn: dns.CanonicalName(args[0]),
		}

		for c.NextBlock() {
			err = parseBlock(c, &cfg)
			if err != nil {
				return nil, err
			}
		}

		cfgs = append(cfgs, cfg)
	}

	return
}

func parseBlock(c *caddy.Controller, cfg *Config) error {
	switch c.Val() {
	case "pve_endpoint":
		args := c.RemainingArgs()
		if len(args) != 1 {
			return c.ArgErr()
		}
		cfg.PveEndpoint = args[0]
	case "pve_insecure_skip_verify":
		args := c.RemainingArgs()
		if len(args) > 0 {
			return c.ArgErr()
		}
		cfg.PveInsecureSkipVerify = true
	case "pve_username":
		args := c.RemainingArgs()
		if len(args) != 1 {
			return c.ArgErr()
		}
		cfg.PveUsername = args[0]
	case "pve_password":
		args := c.RemainingArgs()
		if len(args) != 1 {
			return c.ArgErr()
		}
		cfg.PvePassword = args[0]
	case "pve_password_env":
		args := c.RemainingArgs()
		if len(args) != 1 {
			return c.ArgErr()
		}
		passwd := os.Getenv(args[0])
		if passwd == "" {
			return fmt.Errorf("Environment variable '%s' is not defined", args[0])
		}
		cfg.PvePassword = passwd
	case "pve_realm":
		args := c.RemainingArgs()
		if len(args) != 1 {
			return c.ArgErr()
		}
		cfg.PveRealm = args[0]
	case "pve_otp_env":
		args := c.RemainingArgs()
		if len(args) != 1 {
			return c.ArgErr()
		}
		otp := os.Getenv(args[0])
		if otp == "" {
			return fmt.Errorf("Environment variable '%s' is not defined", args[0])
		}
		cfg.PveOTP = otp
	case "pve_token":
		args := c.RemainingArgs()
		if len(args) != 1 {
			return c.ArgErr()
		}
		cfg.PveToken = args[0]
	case "pve_secret":
		args := c.RemainingArgs()
		if len(args) != 1 {
			return c.ArgErr()
		}
		cfg.PveSecret = args[0]
	case "pve_secret_env":
		args := c.RemainingArgs()
		if len(args) != 1 {
			return c.ArgErr()
		}
		secret := os.Getenv(args[0])
		if secret == "" {
			return fmt.Errorf("Environment variable '%s' is not defined", args[0])
		}
		cfg.PveSecret = secret
	case "pve_pool_as_subdomain":
		args := c.RemainingArgs()
		if len(args) > 0 {
			return c.ArgErr()
		}
		cfg.PvePoolAsSubdomain = true
	case "network":
		args := c.RemainingArgs()
		if len(args) != 1 {
			return c.ArgErr()
		}
		_, network, err := net.ParseCIDR(args[0])
		if err != nil {
			return fmt.Errorf("Error parsing network: %v", err)
		}
		cfg.Network = network
	case "ttl":
		args := c.RemainingArgs()
		if len(args) != 1 {
			return c.ArgErr()
		}
		ttl, err := strconv.ParseUint(args[0], 10, 32)
		if err != nil {
			return fmt.Errorf("Error parsing TTL: %v", err)
		}
		cfg.TTL = uint32(ttl)
	default:
		return fmt.Errorf("Unknown property '%s' at %d line", c.Val(), c.Line())
	}
	return nil
}
