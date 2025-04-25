package pveresolve

import "net"

type Config struct {
	ZoneFqdn              string
	PveEndpoint           string
	PveInsecureSkipVerify bool
	PveUsername           string
	PvePassword           string
	PveRealm              string
	PveOTP                string
	PveToken              string
	PveSecret             string
	PvePoolAsSubdomain    bool
	Network               *net.IPNet
	TTL                   uint32
}
