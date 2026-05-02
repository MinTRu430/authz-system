CREATE TABLE IF NOT EXISTS policy_versions (
  id bigserial PRIMARY KEY,
  version text UNIQUE NOT NULL,
  content_yaml text NOT NULL,
  content_hash text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  created_by text NOT NULL,
  activated_at timestamptz,
  comment text,
  validation_error text
);

CREATE TABLE IF NOT EXISTS policy_active (
  id smallint PRIMARY KEY CHECK (id = 1),
  version_id bigint NOT NULL REFERENCES policy_versions(id),
  activated_at timestamptz NOT NULL DEFAULT now(),
  activated_by text NOT NULL
);

CREATE TABLE IF NOT EXISTS policy_audit (
  id bigserial PRIMARY KEY,
  action text NOT NULL,
  actor text NOT NULL,
  old_version text,
  new_version text,
  status text NOT NULL,
  message text,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_policy_versions_version ON policy_versions(version);
CREATE INDEX IF NOT EXISTS idx_policy_versions_content_hash ON policy_versions(content_hash);
CREATE INDEX IF NOT EXISTS idx_policy_audit_created_at ON policy_audit(created_at);
