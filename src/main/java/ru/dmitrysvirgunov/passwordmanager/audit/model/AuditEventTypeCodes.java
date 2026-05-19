package ru.dmitrysvirgunov.passwordmanager.audit.model;

public final class AuditEventTypeCodes {

    private AuditEventTypeCodes() {
    }

    public static final String USER_REGISTERED = "AUTH.USER_REGISTERED";
    public static final String LOGIN_SUCCEEDED = "AUTH.LOGIN_SUCCEEDED";
    public static final String REFRESH_SUCCEEDED = "AUTH.REFRESH_SUCCEEDED";
    public static final String LOGOUT_SUCCEEDED = "AUTH.LOGOUT_SUCCEEDED";
    public static final String PASSWORD_CHANGED = "AUTH.PASSWORD_CHANGED";
    public static final String USER_KEYS_ROTATED = "AUTH.KEYS_ROTATED";
    public static final String ACCOUNT_DELETED = "AUTH.ACCOUNT_DELETED";

    public static final String VAULT_CREATED = "VAULT.CREATED";
    public static final String VAULT_DELETED = "VAULT.DELETED";
    public static final String VAULT_KEY_ROTATED = "VAULT.KEY_ROTATED";

    public static final String OBJECT_CREATED = "VAULT.OBJECT_CREATED";
    public static final String OBJECT_UPDATED = "VAULT.OBJECT_UPDATED";
    public static final String OBJECT_DELETED = "VAULT.OBJECT_DELETED";

    public static final String INVITE_CREATED = "VAULT.INVITE_CREATED";
    public static final String INVITE_REVOKED = "VAULT.INVITE_REVOKED";
    public static final String INVITE_ACCEPTED = "VAULT.INVITE_ACCEPTED";
    public static final String INVITE_DECLINED = "VAULT.INVITE_DECLINED";

    public static final String MEMBER_ROLE_CHANGED = "VAULT.MEMBER_ROLE_CHANGED";
    public static final String OWNERSHIP_TRANSFERRED = "VAULT.OWNERSHIP_TRANSFERRED";
    public static final String MEMBER_REVOKED = "VAULT.MEMBER_REVOKED";

    public static final String RECORD_KEY_ROTATED = "RECORD_KEY_ROTATED";
}
