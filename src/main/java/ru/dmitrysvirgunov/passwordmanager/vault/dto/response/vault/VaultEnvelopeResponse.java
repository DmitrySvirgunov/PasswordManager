package ru.dmitrysvirgunov.passwordmanager.vault.dto.response.vault;

import tools.jackson.databind.JsonNode;

import java.time.OffsetDateTime;

public record VaultEnvelopeResponse(
        int vaultKeyVersion,
        int recipientEncryptionKeyVersion,
        int envelopeVersion,
        String encryptedVaultKeyBase64,
        JsonNode envelopeParams,
        OffsetDateTime createdAt
) {
}