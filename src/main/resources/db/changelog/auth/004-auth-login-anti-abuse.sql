--liquibase formatted sql

--changeset 004-auth-login-anti-abuse:auth-attempts-decision-failed
alter table auth_attempts
    drop constraint chk_auth_attempts_decision;

alter table auth_attempts
    add constraint chk_auth_attempts_decision
        check (decision in (
            'ALLOWED',
            'FAILED',
            'BLOCKED'
        ));

--changeset 004-auth-login-anti-abuse:auth-attempts-reason-invalid-credentials
alter table auth_attempts
    drop constraint chk_auth_attempts_reason_code;

alter table auth_attempts
    add constraint chk_auth_attempts_reason_code
        check (reason_code in (
            'EMAIL_RATE_LIMIT',
            'IP_RATE_LIMIT',
            'EMAIL_AND_IP_RATE_LIMIT',
            'LOGIN_RATE_LIMIT',
            'RESET_RATE_LIMIT',
            'SUSPICIOUS_PATTERN',
            'INVALID_CREDENTIALS',
            'UNKNOWN_EMAIL',
            'INVALID_TOKEN',
            'UNVERIFIED_EMAIL'
        ));
