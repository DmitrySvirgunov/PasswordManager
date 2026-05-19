package ru.dmitrysvirgunov.passwordmanager.vault.dto.response.command;

import java.time.OffsetDateTime;
import java.util.UUID;

public record CreateVaultResponse(
        UUID vaultId,
        OffsetDateTime createdAt
) {
}