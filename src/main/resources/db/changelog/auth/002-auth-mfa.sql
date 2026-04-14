--liquibase formatted sql

--changeset 002-auth-mfa:user-totp
create table user_totp (
    user_id uuid primary key,
    secret_enc bytea not null,
    enabled_at timestamptz null,
    confirmed_at timestamptz null,
    revoked_at timestamptz null,
    constraint fk_user_totp_user
        foreign key (user_id) references users(user_id) on delete cascade
);

--changeset 002-auth-mfa:user-backup-codes
create table user_backup_codes (
    backup_code_id uuid primary key,
    user_id uuid not null,
    code_hash bytea not null,
    used_at timestamptz null,
    created_at timestamptz not null default now(),
    constraint fk_user_backup_codes_user
        foreign key (user_id) references users(user_id) on delete cascade
);

--changeset 002-auth-mfa:user-passkeys
create table user_passkeys (
    passkey_id uuid primary key,
    user_id uuid not null,
    credential_id bytea not null,
    public_key bytea not null,
    sign_count bigint not null default 0,
    transports jsonb null,
    device_name text null,
    aaguid uuid null,
    created_at timestamptz not null default now(),
    last_used_at timestamptz null,
    revoked_at timestamptz null,
    constraint fk_user_passkeys_user
        foreign key (user_id) references users(user_id) on delete cascade
);