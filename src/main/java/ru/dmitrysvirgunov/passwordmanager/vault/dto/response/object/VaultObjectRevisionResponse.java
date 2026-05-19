package ru.dmitrysvirgunov.passwordmanager.vault.dto.response.object;

import ru.dmitrysvirgunov.passwordmanager.common.model.AeadParams;
import ru.dmitrysvirgunov.passwordmanager.vault.dto.response.blob.VaultBlobReferenceResponse;
import tools.jackson.databind.JsonNode;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;

public record VaultObjectRevisionResponse(
        UUID revisionId,
        UUID objectId,
        int version,
        String ciphertextBase64,
        AeadParams contentAeadParams,
        String wrappedRecordKeyBase64,
        JsonNode recordKeyWrapParams,
        int recordKeyWrappedByVaultKeyVersion,
        String encryptedPackageHashBase64,
        String clientSignatureBase64,
        int signatureFormatVersion,
        int signatureKeyVersion,
        VaultObjectSignatureVerificationResponse signatureVerification,
        UUID signedByUserId,
        String signedByEmail,
        OffsetDateTime createdAt,
        List<VaultBlobReferenceResponse> blobReferences
) {
}
