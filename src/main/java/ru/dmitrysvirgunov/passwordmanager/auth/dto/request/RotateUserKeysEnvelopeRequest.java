package ru.dmitrysvirgunov.passwordmanager.auth.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import tools.jackson.databind.JsonNode;

import java.util.UUID;

public record RotateUserKeysEnvelopeRequest(

        @NotNull
        UUID vaultId,

        @NotBlank
        String encryptedVaultKeyBase64,

        @NotNull
        JsonNode envelopeParams

) {
}
