--liquibase formatted sql

--changeset dmitrysvirgunov:007-vault-blob-indexes

create index ix_vault_blobs_vault_id
    on vault_blobs (vault_id);

create index ix_vault_blobs_vault_id_status
    on vault_blobs (vault_id, status);

create index ix_vault_blob_parts_blob_id
    on vault_blob_parts (blob_id);

create index ix_vault_object_revision_blobs_blob_id
    on vault_object_revision_blobs (blob_id);
