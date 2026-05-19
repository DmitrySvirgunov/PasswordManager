package ru.dmitrysvirgunov.passwordmanager.auth.dto.request;

import jakarta.validation.constraints.NotBlank;

public record AeadParamsRequest(

        @NotBlank
        String algorithm,

        @NotBlank
        String ivBase64
) {
}
