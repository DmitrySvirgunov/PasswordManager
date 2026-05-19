package ru.dmitrysvirgunov.passwordmanager.auth.dto.request;

import jakarta.validation.constraints.NotBlank;

public record DeleteAccountRequest(

        @NotBlank
        String currentAuthSecretBase64
) {
}
