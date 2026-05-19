--liquibase formatted sql

--changeset dmitrysvirgunov:006-vault-blobs

create table vault_blobs (
    blob_id uuid primary key,

    vault_id uuid not null,
    status text not null,

    ciphertext_size_bytes bigint not null,
    chunk_size_bytes int not null,
    chunk_count int not null,
    ciphertext_sha256 bytea null,

    created_by_user_id uuid not null,
    created_at timestamptz not null default now(),
    completed_at timestamptz null,

    constraint fk_vault_blobs_vault
        foreign key (vault_id) references vaults(vault_id) on delete cascade,
    constraint fk_vault_blobs_created_by_user
        foreign key (created_by_user_id) references users(user_id) on delete restrict,

    constraint chk_vault_blobs_status
        check (status in ('PENDING', 'READY', 'ABORTED')),
    constraint chk_vault_blobs_ciphertext_size
        check (ciphertext_size_bytes > 0),
    constraint chk_vault_blobs_chunk_size
        check (chunk_size_bytes > 0),
    constraint chk_vault_blobs_chunk_count
        check (chunk_count > 0)
);

create table vault_blob_parts (
    blob_id uuid not null,
    part_number int not null,

    ciphertext bytea not null,
    ciphertext_sha256 bytea not null,
    ciphertext_size_bytes int not null,

    created_at timestamptz not null default now(),

    constraint pk_vault_blob_parts
        primary key (blob_id, part_number),

    constraint fk_vault_blob_parts_blob
        foreign key (blob_id) references vault_blobs(blob_id) on delete cascade,

    constraint chk_vault_blob_parts_part_number
        check (part_number >= 1),
    constraint chk_vault_blob_parts_ciphertext_size
        check (ciphertext_size_bytes > 0)
);

create table vault_object_revision_blobs (
    revision_id uuid not null,
    role text not null,
    blob_id uuid not null,

    created_at timestamptz not null default now(),

    constraint pk_vault_object_revision_blobs
        primary key (revision_id, role),

    constraint fk_vault_object_revision_blobs_revision
        foreign key (revision_id) references vault_object_revisions(revision_id) on delete cascade,
    constraint fk_vault_object_revision_blobs_blob
        foreign key (blob_id) references vault_blobs(blob_id) on delete restrict,

    constraint chk_vault_object_revision_blobs_role
        check (role in ('PRIMARY', 'PREVIEW', 'THUMBNAIL'))
);
