create table vaults (
    vault_id uuid primary key,
    created_by_user_id uuid not null,

    name_ciphertext bytea not null,
    name_aead_params jsonb not null,

    vault_version int not null default 1,
    current_vault_key_version int not null default 1,

    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),

    constraint fk_vaults_created_by_user
        foreign key (created_by_user_id) references users(user_id) on delete restrict
);

create table vault_members (
    vault_id uuid not null,
    user_id uuid not null,

    role text not null,
    status text not null,
    joined_at timestamptz not null default now(),
    revoked_at timestamptz null,
    expires_at timestamptz null,

    constraint pk_vault_members
        primary key (vault_id, user_id),

    constraint fk_vault_members_vault
        foreign key (vault_id) references vaults(vault_id) on delete cascade,
    constraint fk_vault_members_user
        foreign key (user_id) references users(user_id) on delete cascade,

    constraint chk_vault_members_role
        check (role in ('OWNER', 'EDITOR', 'READER')),
    constraint chk_vault_members_status
        check (status in ('ACTIVE', 'INVITED', 'REVOKED', 'EXPIRED'))
);

create table vault_invites (
    invite_id uuid primary key,

    vault_id uuid not null,
    created_by_user_id uuid not null,

    invitee_user_id uuid not null,
    invitee_email text not null,

    role text not null,
    status text not null,

    created_at timestamptz not null default now(),
    expires_at timestamptz not null,
    accepted_at timestamptz null,
    revoked_at timestamptz null,

    constraint fk_vault_invites_vault
        foreign key (vault_id) references vaults(vault_id) on delete cascade,
    constraint fk_vault_invites_created_by_user
        foreign key (created_by_user_id) references users(user_id) on delete restrict,
    constraint fk_vault_invites_invitee_user
        foreign key (invitee_user_id) references users(user_id) on delete cascade,

    constraint chk_vault_invites_role
        check (role in ('EDITOR', 'READER')),
    constraint chk_vault_invites_status
        check (status in ('PENDING', 'ACCEPTED', 'REVOKED', 'DECLINED', 'EXPIRED')),
    constraint chk_vault_invites_expiry
        check (expires_at > created_at)
);

create unique index uq_vault_invites_pending_per_vault_user
    on vault_invites (vault_id, invitee_user_id)
    where status = 'PENDING' and revoked_at is null;

create table vault_key_envelopes (
    envelope_id uuid primary key,

    vault_id uuid not null,
    vault_key_version int not null,
    recipient_user_id uuid not null,
    recipient_encryption_key_version int not null,

    envelope_version int not null default 1,
    encrypted_vault_key bytea not null,
    envelope_params jsonb not null,

    created_by_user_id uuid not null,
    created_at timestamptz not null default now(),
    revoked_at timestamptz null,

    constraint fk_vault_key_envelopes_vault
        foreign key (vault_id) references vaults(vault_id) on delete cascade,
    constraint fk_vault_key_envelopes_recipient_user
        foreign key (recipient_user_id) references users(user_id) on delete cascade,
    constraint fk_vault_key_envelopes_created_by_user
        foreign key (created_by_user_id) references users(user_id) on delete restrict
);

create unique index uq_vault_key_envelopes_active
    on vault_key_envelopes (
        vault_id,
        recipient_user_id,
        vault_key_version,
        recipient_encryption_key_version
    )
    where revoked_at is null;

create table vault_objects (
    object_id uuid primary key,

    vault_id uuid not null,
    current_version int not null default 1,
    deleted boolean not null default false,

    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),

    constraint fk_vault_objects_vault
        foreign key (vault_id) references vaults(vault_id) on delete cascade
);

create table vault_object_revisions (
    revision_id uuid primary key,

    object_id uuid not null,
    version int not null,

    ciphertext bytea not null,
    content_aead_params jsonb not null,

    wrapped_record_key bytea not null,
    record_key_wrap_params jsonb not null,
    record_key_wrapped_by_vault_key_version int not null,

    encrypted_package_hash bytea not null,

    client_signature bytea not null,
    signature_key_version int not null,
    signed_by_user_id uuid null,

    created_at timestamptz not null default now(),

    constraint fk_vault_object_revisions_object
        foreign key (object_id) references vault_objects(object_id) on delete cascade,
    constraint fk_vault_object_revisions_signed_by_user
        foreign key (signed_by_user_id) references users(user_id) on delete set null,

    constraint uq_vault_object_revisions_object_version
        unique (object_id, version)
);

create table sync_log (
    seq bigserial primary key,

    vault_id uuid not null,
    object_id uuid null,
    version int null,
    actor_user_id uuid not null,
    op_type text not null,

    created_at timestamptz not null default now(),

    constraint fk_sync_log_vault
        foreign key (vault_id) references vaults(vault_id) on delete cascade,
    constraint fk_sync_log_object
        foreign key (object_id) references vault_objects(object_id) on delete cascade,
    constraint fk_sync_log_actor_user
        foreign key (actor_user_id) references users(user_id) on delete restrict,

    constraint chk_sync_log_op_type
        check (op_type in ('UPSERT', 'DELETE', 'ROTATE_VAULT_KEY', 'MEMBERSHIP_CHANGED')),

    constraint chk_sync_log_object_event_shape
        check (
            (op_type in ('UPSERT', 'DELETE') and object_id is not null and version is not null)
            or
            (op_type in ('ROTATE_VAULT_KEY', 'MEMBERSHIP_CHANGED'))
        )
);

create table audit_events (
    event_id bigserial primary key,

    actor_user_id uuid null,

    scope_type text not null,
    scope_id uuid not null,

    event_type text not null,
    meta jsonb null,

    event_hash bytea not null,
    prev_event_hash bytea null,

    signature_key_id text not null,
    event_signature bytea not null,

    created_at timestamptz not null default now(),

    constraint fk_audit_events_actor_user
        foreign key (actor_user_id) references users(user_id) on delete set null,

    constraint chk_audit_events_scope_type
        check (scope_type in ('VAULT', 'USER'))
);
