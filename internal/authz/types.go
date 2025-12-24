package authz

type CheckRequest struct {
	SourceService string `json:"source_service"`
	TargetService string `json:"target_service"`
	RPCMethod     string `json:"rpc_method"`
}

type CheckResponse struct {
	Allow  bool   `json:"allow"`
	Reason string `json:"reason,omitempty"`
	RuleID string `json:"rule_id,omitempty"`
}
