package authz

import "time"

type Config struct {
	TargetService                    string
	PolicyURL                        string // https://policy-server:8443
	PolicyURLs                       []string
	FailOpen                         bool
	Timeout                          time.Duration
	CacheTTL                         time.Duration
	PolicyClientTLS                  TLSFiles
	PolicyHealthTimeout              time.Duration
	PolicyHealthPositiveTTL          time.Duration
	PolicyUnavailableBackoff         time.Duration
	BrokerSigningMode                string
	BrokerSigningSecret              string
	BrokerVerificationSecrets        string
	BrokerMessageMaxAge              time.Duration
	BrokerMessageFutureSkew          time.Duration
	BrokerDLQEnabled                 bool
	BrokerDLQPrefix                  string
	BrokerMaxRetries                 int
	BrokerRetryBackoff               time.Duration
	BrokerDeadLetterOnDeny           bool
	BrokerDeadLetterOnSignatureError bool
}
