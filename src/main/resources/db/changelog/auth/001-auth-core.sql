--liquibase formatted sql

--changeset 001-auth-core:users
create table users (
    user_id uuid primary key,
    email text not null,
    status text not null,
    email_verified_at timestamptz not null,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    constraint chk_users_status
        check (status in ('ACTIVE', 'BLOCKED', 'DELETED'))
);

--changeset 001-auth-core:user-auth
create table user_auth (
    user_id uuid primary key,
    auth_hash bytea not null,
    auth_salt bytea not null,
    auth_hash_params jsonb not null,
    client_kdf_params jsonb not null,
    auth_version int not null default 2,
    password_changed_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),

    constraint fk_user_auth_user
        foreign key (user_id) references users(user_id) on delete cascade
);

--changeset 001-auth-core:user-key-material
create table user_key_material (
    user_id uuid primary key,

    wrapped_account_root_key bytea not null,
    account_root_wrap_params jsonb not null,
    account_root_version int not null default 1,

    public_encryption_key bytea not null,
    encrypted_private_encryption_key bytea not null,
    encryption_key_params jsonb not null,
    encryption_key_version int not null default 1,

    public_signing_key bytea not null,
    encrypted_private_signing_key bytea not null,
    signing_key_params jsonb not null,
    signing_key_version int not null default 1,

    created_at timestamptz not null default now(),
    rotated_at timestamptz null,

    constraint fk_user_key_material_user
        foreign key (user_id) references users(user_id) on delete cascade
);

--changeset 001-auth-core:pending-registrations
create table pending_registrations (
    pending_registration_id uuid primary key,
    email text not null,

    auth_hash bytea not null,
    auth_salt bytea not null,
    auth_hash_params jsonb not null,
    client_kdf_params jsonb not null,

    wrapped_account_root_key bytea not null,
    account_root_wrap_params jsonb not null,
    account_root_version int not null default 1,

    public_encryption_key bytea not null,
    encrypted_private_encryption_key bytea not null,
    encryption_key_params jsonb not null,
    encryption_key_version int not null default 1,

    public_signing_key bytea not null,
    encrypted_private_signing_key bytea not null,
    signing_key_params jsonb not null,
    signing_key_version int not null default 1,

    token_hash bytea not null,
    request_ip_hash bytea null,
    user_agent_hash bytea null,
    expires_at timestamptz not null,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    used_at timestamptz null,

    constraint uq_pending_registrations_token_hash
        unique (token_hash),
    constraint chk_pending_registrations_expiry
        check (expires_at > created_at)
);

create unique index uq_pending_registrations_email_ci_active
    on pending_registrations (lower(email))
    where used_at is null;

--changeset 001-auth-core:user-sessions
create table user_sessions (
    session_id uuid primary key,
    user_id uuid not null,
    refresh_token_hash bytea not null,
    device_name text null,
    user_agent_hash bytea null,
    ip_hash bytea null,
    created_at timestamptz not null default now(),
    expires_at timestamptz not null,
    revoked_at timestamptz null,
    last_seen_at timestamptz null,
    constraint fk_user_sessions_user
        foreign key (user_id) references users(user_id) on delete cascade,
    constraint uq_user_sessions_refresh_token_hash
        unique (refresh_token_hash)
);

--changeset 001-auth-core:auth-attempts
create table auth_attempts (
    attempt_id uuid primary key,

    flow text not null,
    user_id uuid null,

    email_hash bytea null,
    request_ip_hash bytea not null,
    user_agent_hash bytea null,

    decision text not null,
    reason_code text null,
    meta jsonb null,

    created_at timestamptz not null default now(),

    constraint fk_auth_attempts_user
        foreign key (user_id) references users(user_id) on delete set null,

    constraint chk_auth_attempts_flow
        check (flow in (
            'REGISTER',
            'LOGIN',
            'RESEND_VERIFICATION',
            'PASSWORD_RESET_REQUEST',
            'MFA_RESET',
            'NEW_DEVICE_CONFIRMATION'
        )),

    constraint chk_auth_attempts_decision
        check (decision in (
            'ALLOWED',
            'BLOCKED'
        )),

    constraint chk_auth_attempts_reason_code
        check (reason_code in (
            'EMAIL_RATE_LIMIT',
            'IP_RATE_LIMIT',
            'EMAIL_AND_IP_RATE_LIMIT',
            'LOGIN_RATE_LIMIT',
            'RESET_RATE_LIMIT',
            'SUSPICIOUS_PATTERN',
            'UNKNOWN_EMAIL',
            'INVALID_TOKEN',
            'UNVERIFIED_EMAIL'
        ))
);