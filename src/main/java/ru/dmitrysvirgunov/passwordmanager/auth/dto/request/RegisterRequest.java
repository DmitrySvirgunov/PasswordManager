package ru.dmitrysvirgunov.passwordmanager.auth.dto.request;

import jakarta.validation.Valid;
import jakarta.validation.constraints.*;

public record RegisterRequest(

        @NotBlank
        @Email
        @Size(max = 320)
        String email,

        @NotBlank
        String authSecretBase64,

        @NotNull
        @Valid
        KdfParamsRequest clientKdfParams,

        @NotBlank
        String publicKeyBase64,

        @NotBlank
        String encryptedPrivateKeyBase64,

        @NotNull
        @Valid
        KeyParamsRequest keyParams

) {}
