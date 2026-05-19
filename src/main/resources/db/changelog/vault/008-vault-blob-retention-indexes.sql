--liquibase formatted sql

--changeset dmitrysvirgunov:008-vault-blob-retention-indexes

create index ix_vault_blobs_status_created_at
    on vault_blobs (status, created_at);

create index ix_vault_blobs_status_completed_at
    on vault_blobs (status, completed_at);
