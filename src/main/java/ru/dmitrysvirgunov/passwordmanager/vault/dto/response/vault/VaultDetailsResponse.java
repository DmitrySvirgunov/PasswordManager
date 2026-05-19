package ru.dmitrysvirgunov.passwordmanager.vault.dto.response.vault;

import ru.dmitrysvirgunov.passwordmanager.common.model.AeadParams;
import ru.dmitrysvirgunov.passwordmanager.vault.model.VaultMemberRole;
import ru.dmitrysvirgunov.passwordmanager.vault.model.VaultMemberStatus;

import java.time.OffsetDateTime;
import java.util.UUID;

public record VaultDetailsResponse(
        UUID vaultId,
        String nameCiphertextBase64,
        AeadParams nameAeadParams,
        int vaultVersion,
        int currentVaultKeyVersion,
        OffsetDateTime createdAt,
        OffsetDateTime updatedAt,

        VaultMemberRole role,
        VaultMemberStatus status,
        OffsetDateTime joinedAt,
        OffsetDateTime expiresAt,

        VaultEnvelopeResponse myEnvelope
) {
}