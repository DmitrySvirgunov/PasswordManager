package ru.dmitrysvirgunov.passwordmanager.vault.dto.response.command;

import ru.dmitrysvirgunov.passwordmanager.vault.model.VaultBlobStatus;

import java.time.OffsetDateTime;
import java.util.UUID;

public record CreateVaultBlobResponse(
        UUID blobId,
        VaultBlobStatus status,
        OffsetDateTime createdAt
) {
}
