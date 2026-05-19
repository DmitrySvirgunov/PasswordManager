--liquibase formatted sql

--changeset dmitrysvirgunov:012-vault-delete-tombstone

alter table sync_log
    alter column vault_id drop not null;

alter table sync_log
    add column vault_ref_id uuid null;

alter table sync_log
    drop constraint chk_sync_log_op_type;

alter table sync_log
    add constraint chk_sync_log_op_type
        check (op_type in ('UPSERT', 'DELETE', 'ROTATE_VAULT_KEY', 'MEMBERSHIP_CHANGED', 'VAULT_DELETED'));

alter table sync_log
    drop constraint chk_sync_log_object_event_shape;

alter table sync_log
    add constraint chk_sync_log_object_event_shape
        check (
            (op_type in ('UPSERT', 'DELETE')
                and vault_id is not null
                and vault_ref_id is null
                and object_id is not null
                and version is not null)
            or
            (op_type in ('ROTATE_VAULT_KEY', 'MEMBERSHIP_CHANGED')
                and vault_id is not null
                and vault_ref_id is null)
            or
            (op_type = 'VAULT_DELETED'
                and vault_id is null
                and vault_ref_id is not null
                and object_id is null
                and version is null)
        );

create index ix_sync_log_vault_ref_id
    on sync_log (vault_ref_id)
    where vault_ref_id is not null;
