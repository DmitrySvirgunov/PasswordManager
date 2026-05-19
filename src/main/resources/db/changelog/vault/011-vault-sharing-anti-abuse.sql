--liquibase formatted sql

--changeset 011-vault-sharing-anti-abuse:create-vault-sharing-attempts
create table vault_sharing_attempts (
    attempt_id uuid primary key,
    action text not null,
    actor_user_id uuid not null,
    vault_id uuid not null,
    target_email_hash bytea null,
    decision text not null,
    meta jsonb null,
    created_at timestamptz not null default now(),

    constraint fk_vault_sharing_attempts_actor
        foreign key (actor_user_id) references users(user_id) on delete cascade,
    constraint fk_vault_sharing_attempts_vault
        foreign key (vault_id) references vaults(vault_id) on delete cascade,
    constraint chk_vault_sharing_attempts_action
        check (action in (
            'INVITEE_KEY_LOOKUP',
            'CREATE_INVITE'
        )),
    constraint chk_vault_sharing_attempts_decision
        check (decision in (
            'ALLOWED',
            'BLOCKED'
        ))
);

--changeset 011-vault-sharing-anti-abuse:idx-vault-sharing-attempts-action-actor-created-at
create index ix_vault_sharing_attempts_action_actor_created_at
    on vault_sharing_attempts (action, actor_user_id, created_at);

--changeset 011-vault-sharing-anti-abuse:idx-vault-sharing-attempts-action-vault-created-at
create index ix_vault_sharing_attempts_action_vault_created_at
    on vault_sharing_attempts (action, vault_id, created_at);

--changeset 011-vault-sharing-anti-abuse:idx-vault-sharing-attempts-action-actor-target-created-at
create index ix_vault_sharing_attempts_action_actor_target_created_at
    on vault_sharing_attempts (action, actor_user_id, target_email_hash, created_at);
