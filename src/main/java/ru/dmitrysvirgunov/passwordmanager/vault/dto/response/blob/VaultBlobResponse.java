package ru.dmitrysvirgunov.passwordmanager.vault.dto.response.blob;

import ru.dmitrysvirgunov.passwordmanager.vault.model.VaultBlobStatus;

import java.time.OffsetDateTime;
import java.util.UUID;

public record VaultBlobResponse(
        UUID blobId,
        VaultBlobStatus status,
        long ciphertextSizeBytes,
        int chunkSizeBytes,
        int chunkCount,
        long uploadedPartCount,
        OffsetDateTime createdAt,
        OffsetDateTime completedAt
) {
}
