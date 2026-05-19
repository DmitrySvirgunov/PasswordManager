package ru.dmitrysvirgunov.passwordmanager.auth.dto.request;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;

import java.util.List;

public record RotateUserKeysRequest(

        @NotBlank
        String currentAuthSecretBase64,

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
        AsymmetricKeyParamsRequest signingKeyParams,

        @NotNull
        @Valid
        List<RotateUserKeysEnvelopeRequest> envelopes

) {
}
