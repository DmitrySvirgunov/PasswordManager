package ru.dmitrysvirgunov.passwordmanager.vault.dto.response.command;

import ru.dmitrysvirgunov.passwordmanager.vault.model.VaultBlobStatus;

import java.time.OffsetDateTime;
import java.util.UUID;

public record CompleteVaultBlobUploadResponse(
        UUID blobId,
        VaultBlobStatus status,
        OffsetDateTime completedAt
) {
}
