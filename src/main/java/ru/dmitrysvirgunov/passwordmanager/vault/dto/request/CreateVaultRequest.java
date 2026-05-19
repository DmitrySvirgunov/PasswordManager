package ru.dmitrysvirgunov.passwordmanager.vault.dto.request;

import tools.jackson.databind.JsonNode;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import ru.dmitrysvirgunov.passwordmanager.auth.dto.request.AeadParamsRequest;

public record CreateVaultRequest(

        @NotBlank
        String nameCiphertextBase64,

        @NotNull
        @Valid
        AeadParamsRequest nameAeadParams,

        @NotBlank
        String encryptedVaultKeyBase64,

        @NotNull
        JsonNode envelopeParams

) {
}