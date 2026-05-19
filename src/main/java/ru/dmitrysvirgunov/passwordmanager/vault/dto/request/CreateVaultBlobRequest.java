package ru.dmitrysvirgunov.passwordmanager.vault.dto.request;

import jakarta.validation.constraints.Positive;

public record CreateVaultBlobRequest(

        @Positive
        long ciphertextSizeBytes,

        @Positive
        int chunkSizeBytes,

        @Positive
        int chunkCount

) {
}
