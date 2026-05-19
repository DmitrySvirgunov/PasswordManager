package ru.dmitrysvirgunov.passwordmanager.vault.model;

public enum SyncOpType {
    UPSERT,
    DELETE,
    ROTATE_VAULT_KEY,
    MEMBERSHIP_CHANGED,
    VAULT_DELETED
}
