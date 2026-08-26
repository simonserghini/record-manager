-- Performance indexes: audit log pagination and permission lookups
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs (created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_permissions_user_domain ON permissions (user_id, domain_id);
CREATE INDEX IF NOT EXISTS idx_record_permissions_user_domain_record ON record_permissions (user_id, domain_id, record_id);
CREATE INDEX IF NOT EXISTS idx_record_permissions_record ON record_permissions (record_id);
CREATE INDEX IF NOT EXISTS idx_record_metadata_domain ON record_metadata (domain_id);
