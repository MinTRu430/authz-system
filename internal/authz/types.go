package authz

import "strings"

type Transport string

const (
	TransportGRPC   Transport = "grpc"
	TransportHTTP   Transport = "http"
	TransportREST   Transport = TransportHTTP
	TransportBroker Transport = "broker"
)

type AuthzRequest struct {
	Source      string    `json:"source,omitempty"`
	Target      string    `json:"target,omitempty"`
	Transport   Transport `json:"transport,omitempty"`
	Operation   string    `json:"operation,omitempty"`
	Resource    string    `json:"resource,omitempty"`
	Broker      string    `json:"broker,omitempty"`
	MessageType string    `json:"message_type,omitempty"`

	SourceService string `json:"source_service,omitempty"`
	TargetService string `json:"target_service,omitempty"`
	RPCMethod     string `json:"rpc_method,omitempty"`
}

type CheckRequest = AuthzRequest

type CheckResponse struct {
	Allow   bool   `json:"allow"`
	Reason  string `json:"reason,omitempty"`
	RuleID  string `json:"rule_id,omitempty"`
	Version string `json:"version,omitempty"`
}

func NewAuthzRequest(source, target string, transport Transport, operation, resource string) AuthzRequest {
	return AuthzRequest{
		Source:    source,
		Target:    target,
		Transport: transport,
		Operation: operation,
		Resource:  resource,
	}.Normalize()
}

func NewGRPCAuthzRequest(source, target, fullMethod string) AuthzRequest {
	return NewAuthzRequest(source, target, TransportGRPC, fullMethod, "*")
}

func (r AuthzRequest) Normalize() AuthzRequest {
	r.Transport = normalizeTransport(r.Transport)
	if r.Source == "" {
		r.Source = r.SourceService
	}
	if r.Target == "" {
		r.Target = r.TargetService
	}
	if r.Transport == "" && r.RPCMethod != "" {
		r.Transport = TransportGRPC
	}
	if r.Operation == "" && r.RPCMethod != "" {
		r.Operation = r.RPCMethod
	}
	if r.Resource == "" {
		r.Resource = "*"
	}
	if r.Broker == "" {
		r.Broker = "*"
	}
	if r.MessageType == "" {
		r.MessageType = "*"
	}
	return r
}

func normalizeTransport(t Transport) Transport {
	switch strings.ToLower(string(t)) {
	case "rest":
		return TransportHTTP
	default:
		return Transport(strings.ToLower(string(t)))
	}
}
