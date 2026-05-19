package ru.dmitrysvirgunov.passwordmanager.vault.dto.response.object;

public record VaultObjectSignatureVerificationResponse(
        VaultObjectSignatureVerificationStatus status,
        VaultObjectSignatureKeySource keySource
) {
}
