package ru.dmitrysvirgunov.passwordmanager.vault.dto.request;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import tools.jackson.databind.JsonNode;

import java.util.UUID;

public record RotateVaultKeyEnvelopeRequest(

        @NotNull
        UUID recipientUserId,

        @Min(1)
        int recipientEncryptionKeyVersion,

        @NotBlank
        String encryptedVaultKeyBase64,

        @NotNull
        JsonNode envelopeParams

) {
}