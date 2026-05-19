package ru.dmitrysvirgunov.passwordmanager.vault.dto.response.blob;

import java.util.UUID;

public record VaultBlobPartResponse(
        UUID blobId,
        int partNumber,
        byte[] ciphertextChunk,
        byte[] ciphertextChunkSha256,
        int ciphertextSizeBytes
) {
}
