--liquibase formatted sql

--changeset 003-auth-indexes:users-email-lower
create unique index ux_users_email_lower
    on users (lower(email));

--changeset 003-auth-indexes:user-sessions-user-id
create index ix_user_sessions_user_id
    on user_sessions (user_id);

--changeset 003-auth-indexes:user-sessions-expires-at
create index ix_user_sessions_expires_at
    on user_sessions (expires_at);

--changeset 003-auth-indexes:user-sessions-user-id-revoked-at
create index ix_user_sessions_user_id_revoked_at
    on user_sessions (user_id, revoked_at);

--changeset 003-auth-indexes:user-auth-tokens-user-id-purpose
create index ix_user_auth_tokens_user_id_purpose
    on user_auth_tokens (user_id, purpose);

--changeset 003-auth-indexes:user-auth-tokens-expires-at
create index ix_user_auth_tokens_expires_at
    on user_auth_tokens (expires_at);

--changeset 003-auth-indexes:user-backup-codes-user-id
create index ix_user_backup_codes_user_id
    on user_backup_codes (user_id);

--changeset 003-auth-indexes:user-passkeys-user-id
create index ix_user_passkeys_user_id
    on user_passkeys (user_id);

--changeset 003-auth-indexes:user-passkeys-credential-id
create unique index ux_user_passkeys_credential_id
    on user_passkeys (credential_id);

--changeset 003-auth-core:idx-pending-registrations-expires-at
create index idx_pending_registrations_expires_at
    on pending_registrations (expires_at);

--changeset 003-auth-core:idx-auth-attempts-flow-email-created-at
create index idx_auth_attempts_flow_email_created_at
    on auth_attempts (flow, email_hash, created_at);

--changeset 003-auth-core:idx-auth-attempts-flow-ip-created-at
create index idx_auth_attempts_flow_ip_created_at
    on auth_attempts (flow, request_ip_hash, created_at);

--changeset 003-auth-core:idx-auth-attempts-user-created-at
create index idx_auth_attempts_user_created_at
    on auth_attempts (user_id, created_at);

--changeset 003-auth-core:idx-auth-attempts-created-at
create index idx_auth_attempts_created_at
    on auth_attempts (created_at);
