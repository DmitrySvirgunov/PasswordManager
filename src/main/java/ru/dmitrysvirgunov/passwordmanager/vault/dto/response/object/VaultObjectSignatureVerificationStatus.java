package ru.dmitrysvirgunov.passwordmanager.vault.dto.response.object;

public enum VaultObjectSignatureVerificationStatus {
    VERIFIED,
    LEGACY_UNVERIFIED,
    KEY_NOT_FOUND,
    HASH_MISMATCH,
    SIGNATURE_INVALID,
    UNSUPPORTED_FORMAT
}
