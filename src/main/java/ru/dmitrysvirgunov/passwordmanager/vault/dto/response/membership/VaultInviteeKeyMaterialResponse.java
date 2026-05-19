package ru.dmitrysvirgunov.passwordmanager.vault.dto.response.membership;

import java.util.UUID;

public record VaultInviteeKeyMaterialResponse(
        UUID userId,
        String email,
        String publicEncryptionKeyBase64,
        int encryptionKeyVersion,
        String keyAlgorithm,
        String publicKeyEncoding
) {
}
