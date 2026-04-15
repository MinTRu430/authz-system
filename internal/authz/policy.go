package authz

import "strings"

type PolicyRule struct {
	ID        string    `json:"id" yaml:"id"`
	Source    string    `json:"source" yaml:"source"`
	Target    string    `json:"target" yaml:"target"`
	Transport Transport `json:"transport,omitempty" yaml:"transport,omitempty"`
	Operation string    `json:"operation,omitempty" yaml:"operation,omitempty"`
	Resource  string    `json:"resource,omitempty" yaml:"resource,omitempty"`
	Effect    string    `json:"effect" yaml:"effect"`

	RPC string `json:"rpc,omitempty" yaml:"rpc,omitempty"`
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
			matchPolicyField(r.Resource, req.Resource) {
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
