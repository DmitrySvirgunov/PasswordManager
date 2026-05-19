--liquibase formatted sql

--changeset dmitrysvirgunov:009-sync-targets

alter table sync_log
    add column target_user_id uuid null,
    add column invite_id uuid null;

alter table sync_log
    add constraint fk_sync_log_target_user
        foreign key (target_user_id) references users(user_id) on delete cascade,
    add constraint fk_sync_log_invite
        foreign key (invite_id) references vault_invites(invite_id) on delete cascade;

create index ix_sync_log_target_user_seq
    on sync_log (target_user_id, seq)
    where target_user_id is not null;

create index ix_sync_log_invite_id
    on sync_log (invite_id)
    where invite_id is not null;
