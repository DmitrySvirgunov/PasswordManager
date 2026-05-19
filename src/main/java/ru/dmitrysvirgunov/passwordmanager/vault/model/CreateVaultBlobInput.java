package ru.dmitrysvirgunov.passwordmanager.vault.model;

public record CreateVaultBlobInput(
        long ciphertextSizeBytes,
        int chunkSizeBytes,
        int chunkCount
) {
}
