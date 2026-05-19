package ru.dmitrysvirgunov.passwordmanager.vault.dto.response.command;

import java.time.OffsetDateTime;
import java.util.UUID;

public record RotateRecordKeyResponse(
        UUID vaultId,
        UUID objectId,
        int previousVersion,
        int newVersion,
        int vaultKeyVersion,
        OffsetDateTime rotatedAt
) {
}