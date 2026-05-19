--liquibase formatted sql

--changeset 007-auth-user-key-rotation:user-key-material-history
create table user_key_material_history (
    history_id uuid primary key,
    user_id uuid not null,

    wrapped_account_root_key bytea not null,
    account_root_wrap_params jsonb not null,
    account_root_version int not null,

    public_encryption_key bytea not null,
    encrypted_private_encryption_key bytea not null,
    encryption_key_params jsonb not null,
    encryption_key_version int not null,

    public_signing_key bytea not null,
    encrypted_private_signing_key bytea not null,
    signing_key_params jsonb not null,
    signing_key_version int not null,

    created_at timestamptz not null,
    rotated_at timestamptz null,
    archived_at timestamptz not null default now(),

    constraint fk_user_key_material_history_user
        foreign key (user_id) references users(user_id) on delete cascade,
    constraint uq_user_key_material_history_user_versions
        unique (user_id, encryption_key_version, signing_key_version)
);

create index idx_user_key_material_history_user_archived_at
    on user_key_material_history (user_id, archived_at desc);
