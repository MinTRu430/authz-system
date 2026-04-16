package authz

import "time"

type Config struct {
	TargetService   string
	PolicyURL       string // https://policy-server:8443
	FailOpen        bool
	Timeout         time.Duration
	CacheTTL        time.Duration
	PolicyClientTLS TLSFiles
}
