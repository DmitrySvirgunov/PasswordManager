package ru.dmitrysvirgunov.passwordmanager.auth.dto.request;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

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
        String wrappedAccountRootKeyBase64,

        @NotNull
        @Valid
        AeadParamsRequest accountRootWrapParams,

        @NotBlank
        String publicEncryptionKeyBase64,

        @NotBlank
        String encryptedPrivateEncryptionKeyBase64,

        @NotNull
        @Valid
        AsymmetricKeyParamsRequest encryptionKeyParams,

        @NotBlank
        String publicSigningKeyBase64,

        @NotBlank
        String encryptedPrivateSigningKeyBase64,

        @NotNull
        @Valid
        AsymmetricKeyParamsRequest signingKeyParams
) {
}