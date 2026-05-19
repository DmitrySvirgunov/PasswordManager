package ru.dmitrysvirgunov.passwordmanager.vault.model;

public record CompleteVaultBlobUploadInput(
        byte[] ciphertextSha256
) {
}
