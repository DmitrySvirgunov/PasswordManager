package ru.dmitrysvirgunov.passwordmanager.auth.dto.request;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

public record KeyParamsRequest(

        @NotBlank
        String keyAlgorithm,     // например: "RSA" или "Ed25519"

        @NotNull
        @Valid
        PrivateKeyWrapParamsRequest privateKeyWrap
) {}
