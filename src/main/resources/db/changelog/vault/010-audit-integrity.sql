create table audit_scope_heads (
    scope_type text not null,
    scope_id uuid not null,
    head_event_id bigint not null,
    head_event_hash bytea not null,
    head_created_at timestamptz not null,
    updated_at timestamptz not null default now(),

    constraint pk_audit_scope_heads
        primary key (scope_type, scope_id),

    constraint fk_audit_scope_heads_head_event
        foreign key (head_event_id) references audit_events(event_id) on delete restrict,

    constraint chk_audit_scope_heads_scope_type
        check (scope_type in ('VAULT', 'USER'))
);

insert into audit_scope_heads (
    scope_type,
    scope_id,
    head_event_id,
    head_event_hash,
    head_created_at,
    updated_at
)
select latest.scope_type,
       latest.scope_id,
       latest.event_id,
       latest.event_hash,
       latest.created_at,
       now()
from (
    select distinct on (scope_type, scope_id)
           scope_type,
           scope_id,
           event_id,
           event_hash,
           created_at
    from audit_events
    order by scope_type, scope_id, event_id desc
) latest;

create table audit_anchor_outbox (
    outbox_id bigserial primary key,
    source_instance_id text not null,
    scope_type text not null,
    scope_id uuid not null,
    event_id bigint not null,
    event_hash bytea not null,
    event_created_at timestamptz not null,
    anchored_at timestamptz not null,

    anchor_payload jsonb not null,
    anchor_key_id text not null,
    anchor_signature bytea not null,

    created_at timestamptz not null default now(),
    exported_at timestamptz null,
    export_attempts integer not null default 0,
    last_error text null,

    constraint uq_audit_anchor_outbox_scope_event
        unique (source_instance_id, scope_type, scope_id, event_id),

    constraint fk_audit_anchor_outbox_event
        foreign key (event_id) references audit_events(event_id) on delete restrict,

    constraint chk_audit_anchor_outbox_scope_type
        check (scope_type in ('VAULT', 'USER'))
);

create index ix_audit_anchor_outbox_pending
    on audit_anchor_outbox (outbox_id)
    where exported_at is null;

create index ix_audit_anchor_outbox_scope_event
    on audit_anchor_outbox (scope_type, scope_id, event_id desc);

create or replace function forbid_audit_event_mutation()
returns trigger
language plpgsql
as $$
begin
    raise exception 'audit_events is append-only';
end;
$$;

create trigger trg_audit_events_no_update
    before update on audit_events
    for each row
execute function forbid_audit_event_mutation();

create trigger trg_audit_events_no_delete
    before delete on audit_events
    for each row
execute function forbid_audit_event_mutation();
