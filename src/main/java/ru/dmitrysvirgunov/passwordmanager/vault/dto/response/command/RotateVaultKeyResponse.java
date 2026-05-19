package ru.dmitrysvirgunov.passwordmanager.vault.dto.response.command;

import java.time.OffsetDateTime;
import java.util.UUID;

public record RotateVaultKeyResponse(
        UUID vaultId,
        int previousVaultKeyVersion,
        int newVaultKeyVersion,
        int rotatedObjectCount,
        OffsetDateTime rotatedAt
) {
}