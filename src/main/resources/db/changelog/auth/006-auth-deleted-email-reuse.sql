--liquibase formatted sql

--changeset 006-auth-deleted-email-reuse:users-email-lower-active
drop index if exists ux_users_email_lower;

create unique index ux_users_email_lower_active
    on users (lower(email))
    where status <> 'DELETED';
