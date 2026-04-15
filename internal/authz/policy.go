package authz

import "strings"

type PolicyRule struct {
	ID          string    `json:"id" yaml:"id"`
	Source      string    `json:"source" yaml:"source"`
	Target      string    `json:"target" yaml:"target"`
	Transport   Transport `json:"transport,omitempty" yaml:"transport,omitempty"`
	Operation   string    `json:"operation,omitempty" yaml:"operation,omitempty"`
	Resource    string    `json:"resource,omitempty" yaml:"resource,omitempty"`
	Broker      string    `json:"broker,omitempty" yaml:"broker,omitempty"`
	Effect      string    `json:"effect" yaml:"effect"`
	MessageType string    `json:"message_type,omitempty" yaml:"message_type,omitempty"`
	RPC         string    `json:"rpc,omitempty" yaml:"rpc,omitempty"`
}

func (r PolicyRule) Normalize() PolicyRule {
	r.Transport = normalizeTransport(r.Transport)
	if r.RPC != "" {
		if r.Transport == "" {
			r.Transport = TransportGRPC
		}
		if r.Operation == "" {
			r.Operation = r.RPC
		}
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
	r.Effect = strings.ToLower(r.Effect)
	return r
}

func NormalizePolicyRules(rules []PolicyRule) []PolicyRule {
	out := make([]PolicyRule, len(rules))
	for i := range rules {
		out[i] = rules[i].Normalize()
	}
	return out
}

func DecidePolicy(rules []PolicyRule, version string, req AuthzRequest) CheckResponse {
	req = req.Normalize()
	resp := CheckResponse{Allow: false, Reason: "default deny", Version: version}

	for _, r := range rules {
		if matchPolicyField(r.Source, req.Source) &&
			matchPolicyField(r.Target, req.Target) &&
			matchPolicyField(string(r.Transport), string(req.Transport)) &&
			matchPolicyField(r.Operation, req.Operation) &&
			matchPolicyField(r.Resource, req.Resource) &&
			matchPolicyField(r.Broker, req.Broker) &&
			matchPolicyField(r.MessageType, req.MessageType) {
			resp.RuleID = r.ID
			resp.Version = version
			if r.Effect == "allow" {
				resp.Allow = true
				resp.Reason = "matched allow rule"
			} else {
				resp.Allow = false
				resp.Reason = "matched deny rule"
			}
			return resp
		}
	}
	return resp
}

func matchPolicyField(rule, val string) bool {
	return rule == "*" || rule == val
}
