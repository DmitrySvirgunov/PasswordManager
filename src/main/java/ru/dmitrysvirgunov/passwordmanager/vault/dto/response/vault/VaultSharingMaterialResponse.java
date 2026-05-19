package ru.dmitrysvirgunov.passwordmanager.vault.dto.response.vault;

import ru.dmitrysvirgunov.passwordmanager.vault.model.VaultMemberRole;

import java.util.UUID;

public record VaultSharingMaterialResponse(
        UUID userId,
        String email,
        VaultMemberRole role,
        String publicEncryptionKeyBase64,
        int encryptionKeyVersion
) {
}