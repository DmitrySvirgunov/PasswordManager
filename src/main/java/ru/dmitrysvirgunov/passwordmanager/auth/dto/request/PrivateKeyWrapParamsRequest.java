package ru.dmitrysvirgunov.passwordmanager.auth.dto.request;

import jakarta.validation.constraints.NotBlank;

public record PrivateKeyWrapParamsRequest(

        @NotBlank
        String algorithm,

        @NotBlank
        String ivBase64,

        @NotBlank
        String saltBase64

) {}
