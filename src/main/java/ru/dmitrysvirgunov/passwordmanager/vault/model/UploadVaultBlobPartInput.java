package ru.dmitrysvirgunov.passwordmanager.vault.model;

public record UploadVaultBlobPartInput(
        byte[] ciphertextChunk,
        byte[] ciphertextChunkSha256
) {
}
