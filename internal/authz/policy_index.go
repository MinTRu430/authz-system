package authz

type PolicyIndexStats struct {
	Rules   int
	Buckets int
}

type CompiledPolicy struct {
	rules   []PolicyRule
	buckets map[policyKey][]int
	stats   PolicyIndexStats
}

type policyKey struct {
	Source      string
	Target      string
	Transport   string
	Operation   string
	Resource    string
	Broker      string
	MessageType string
}

func CompilePolicyRules(rules []PolicyRule) *CompiledPolicy {
	normalized := NormalizePolicyRules(rules)
	buckets := make(map[policyKey][]int, len(normalized))

	for i, rule := range normalized {
		key := policyKeyFromRule(rule)
		buckets[key] = append(buckets[key], i)
	}

	return &CompiledPolicy{
		rules:   normalized,
		buckets: buckets,
		stats: PolicyIndexStats{
			Rules:   len(normalized),
			Buckets: len(buckets),
		},
	}
}

func (p *CompiledPolicy) Stats() PolicyIndexStats {
	if p == nil {
		return PolicyIndexStats{}
	}
	return p.stats
}

func (p *CompiledPolicy) Decide(version string, req AuthzRequest) CheckResponse {
	req = req.Normalize()
	resp := CheckResponse{Allow: false, Reason: "default deny", Version: version}
	if p == nil {
		return resp
	}

	best := -1
	for _, idx := range p.candidateRuleIndexes(req) {
		rule := p.rules[idx]
		if matchPolicyField(rule.Source, req.Source) &&
			matchPolicyField(rule.Target, req.Target) &&
			matchPolicyField(string(rule.Transport), string(req.Transport)) &&
			matchPolicyField(rule.Operation, req.Operation) &&
			matchPolicyField(rule.Resource, req.Resource) &&
			matchPolicyField(rule.Broker, req.Broker) &&
			matchPolicyField(rule.MessageType, req.MessageType) &&
			(best == -1 || idx < best) {
			best = idx
		}
	}

	if best == -1 {
		return resp
	}

	rule := p.rules[best]
	resp.RuleID = rule.ID
	resp.Version = version
	if rule.Effect == "allow" {
		resp.Allow = true
		resp.Reason = "matched allow rule"
	} else {
		resp.Allow = false
		resp.Reason = "matched deny rule"
	}
	return resp
}

func (p *CompiledPolicy) candidateRuleIndexes(req AuthzRequest) []int {
	if p == nil {
		return nil
	}

	seen := make(map[int]struct{})
	out := make([]int, 0)
	for _, key := range candidateKeys(req) {
		for _, idx := range p.buckets[key] {
			if _, ok := seen[idx]; ok {
				continue
			}
			seen[idx] = struct{}{}
			out = append(out, idx)
		}
	}
	return out
}

func candidateKeys(req AuthzRequest) []policyKey {
	req = req.Normalize()

	sources := policyFieldVariants(req.Source)
	targets := policyFieldVariants(req.Target)
	transports := policyFieldVariants(string(req.Transport))
	operations := policyFieldVariants(req.Operation)
	resources := policyFieldVariants(req.Resource)
	brokers := policyFieldVariants(req.Broker)
	messageTypes := policyFieldVariants(req.MessageType)

	keys := make([]policyKey, 0, len(sources)*len(targets)*len(transports)*len(operations)*len(resources)*len(brokers)*len(messageTypes))
	for _, source := range sources {
		for _, target := range targets {
			for _, transport := range transports {
				for _, operation := range operations {
					for _, resource := range resources {
						for _, broker := range brokers {
							for _, messageType := range messageTypes {
								keys = append(keys, policyKey{
									Source:      source,
									Target:      target,
									Transport:   transport,
									Operation:   operation,
									Resource:    resource,
									Broker:      broker,
									MessageType: messageType,
								})
							}
						}
					}
				}
			}
		}
	}
	return keys
}

func policyFieldVariants(value string) []string {
	if value == "*" {
		return []string{"*"}
	}
	return []string{value, "*"}
}

func policyKeyFromRule(rule PolicyRule) policyKey {
	return policyKey{
		Source:      rule.Source,
		Target:      rule.Target,
		Transport:   string(rule.Transport),
		Operation:   rule.Operation,
		Resource:    rule.Resource,
		Broker:      rule.Broker,
		MessageType: rule.MessageType,
	}
}
