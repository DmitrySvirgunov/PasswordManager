package ru.dmitrysvirgunov.passwordmanager.auth.dto.request;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

public record AsymmetricKeyParamsRequest(

        @NotBlank
        String keyAlgorithm,

        @NotBlank
        String publicKeyEncoding,

        @NotBlank
        String privateKeyEncoding,

        @NotNull
        @Valid
        AeadParamsRequest privateKeyWrap

) {
}
