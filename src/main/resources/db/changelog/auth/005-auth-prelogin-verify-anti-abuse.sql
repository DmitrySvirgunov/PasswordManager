--liquibase formatted sql

--changeset 005-auth-prelogin-verify-anti-abuse:auth-attempts-flow-check
alter table auth_attempts
    drop constraint chk_auth_attempts_flow;

alter table auth_attempts
    add constraint chk_auth_attempts_flow
        check (flow in (
            'REGISTER',
            'LOGIN',
            'PRELOGIN',
            'VERIFY_EMAIL',
            'RESEND_VERIFICATION',
            'PASSWORD_RESET_REQUEST',
            'MFA_RESET',
            'NEW_DEVICE_CONFIRMATION'
        ));
