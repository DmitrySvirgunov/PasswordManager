package ru.dmitrysvirgunov.passwordmanager.vault.dto.request;

import jakarta.validation.constraints.NotBlank;

public record CompleteVaultBlobUploadRequest(

        @NotBlank
        String ciphertextSha256Base64

) {
}
