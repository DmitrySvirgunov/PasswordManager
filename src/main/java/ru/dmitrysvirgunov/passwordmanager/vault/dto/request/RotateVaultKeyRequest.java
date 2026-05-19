package ru.dmitrysvirgunov.passwordmanager.vault.dto.request;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import ru.dmitrysvirgunov.passwordmanager.auth.dto.request.AeadParamsRequest;

import java.util.List;

public record RotateVaultKeyRequest(

        @Min(1)
        int expectedCurrentVaultKeyVersion,

        @Min(2)
        int newVaultKeyVersion,

        @NotBlank
        String nameCiphertextBase64,

        @NotNull
        @Valid
        AeadParamsRequest nameAeadParams,

        @NotEmpty
        @Valid
        List<RotateVaultKeyEnvelopeRequest> envelopes,

        @NotNull
        @Valid
        List<RotateVaultObjectRequest> objects

) {
}