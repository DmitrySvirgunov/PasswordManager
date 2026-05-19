package ru.dmitrysvirgunov.passwordmanager.vault.dto.request;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import ru.dmitrysvirgunov.passwordmanager.auth.dto.request.AeadParamsRequest;
import tools.jackson.databind.JsonNode;

import java.util.List;
import java.util.UUID;

public record RotateVaultObjectRequest(

        @NotNull
        UUID objectId,

        @Min(1)
        int expectedCurrentVersion,

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

        @Min(1)
        int signatureFormatVersion,

        @Min(1)
        int signatureKeyVersion,

        @NotNull
        @Valid
        List<BlobReferenceRequest> blobReferences

) {
}
