package ru.dmitrysvirgunov.passwordmanager.vault.dto.request;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import ru.dmitrysvirgunov.passwordmanager.auth.dto.request.AeadParamsRequest;
import tools.jackson.databind.JsonNode;

import java.util.List;

public record DeleteVaultObjectRequest(

        @Positive
        int expectedVersion,

        @NotBlank
        String ciphertextBase64,

        @NotNull
        @Valid
        AeadParamsRequest contentAeadParams,

        @NotBlank
        String wrappedRecordKeyBase64,

        @NotNull
        JsonNode recordKeyWrapParams,

        @NotBlank
        String encryptedPackageHashBase64,

        @NotBlank
        String clientSignatureBase64,

        @Positive
        int signatureFormatVersion,

        @Positive
        int signatureKeyVersion,

        @NotNull
        @Valid
        List<BlobReferenceRequest> blobReferences

) {
}
