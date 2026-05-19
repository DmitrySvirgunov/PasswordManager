create index ix_vault_members_user_id
    on vault_members (user_id);

create index ix_vault_members_vault_id_status
    on vault_members (vault_id, status);

create index ix_vault_invites_vault_id
    on vault_invites (vault_id);

create index ix_vault_invites_invitee_email
    on vault_invites (lower(invitee_email));

create index ix_vault_key_envelopes_recipient_user_id
    on vault_key_envelopes (recipient_user_id);

create index ix_vault_key_envelopes_vault_recipient_key_version
    on vault_key_envelopes (vault_id, recipient_user_id, vault_key_version);

create index ix_vault_objects_vault_id
    on vault_objects (vault_id);

create index ix_vault_objects_vault_id_deleted
    on vault_objects (vault_id, deleted);

create index ix_vault_object_revisions_object_id_created_at
    on vault_object_revisions (object_id, created_at);

create index ix_vault_object_revisions_object_id_vault_key_version
    on vault_object_revisions (object_id, record_key_wrapped_by_vault_key_version);

create index ix_sync_log_vault_id_seq
    on sync_log (vault_id, seq);

create index ix_sync_log_object_id
    on sync_log (object_id);

create index ix_sync_log_actor_user_id
    on sync_log (actor_user_id);

create index ix_audit_events_scope_event_id
    on audit_events (scope_type, scope_id, event_id);

create index ix_audit_events_scope_created_at
    on audit_events (scope_type, scope_id, created_at);

create index ix_audit_events_actor_user_id_created_at
    on audit_events (actor_user_id, created_at);