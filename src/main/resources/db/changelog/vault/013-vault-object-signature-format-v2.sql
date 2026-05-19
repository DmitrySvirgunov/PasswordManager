--liquibase formatted sql

--changeset dmitrysvirgunov:013-vault-object-signature-format-v2

alter table vault_object_revisions
    add column signature_format_version int not null default 1;
