package ru.dmitrysvirgunov.passwordmanager.vault.mapper;

import org.springframework.stereotype.Component;
import ru.dmitrysvirgunov.passwordmanager.vault.dto.response.blob.VaultBlobReferenceResponse;
import ru.dmitrysvirgunov.passwordmanager.vault.dto.response.object.VaultObjectRevisionResponse;
import ru.dmitrysvirgunov.passwordmanager.vault.dto.response.object.VaultObjectSignatureVerificationResponse;
import ru.dmitrysvirgunov.passwordmanager.vault.dto.response.object.VaultObjectSnapshotResponse;
import ru.dmitrysvirgunov.passwordmanager.vault.entity.VaultObject;
import ru.dmitrysvirgunov.passwordmanager.vault.entity.VaultObjectRevision;
import ru.dmitrysvirgunov.passwordmanager.vault.entity.VaultObjectRevisionBlob;

import java.util.List;

import java.util.Base64;

@Component
public class VaultObjectResponseMapper {

    public VaultObjectSnapshotResponse toSnapshotResponse(
            VaultObject object,
            VaultObjectRevision revision,
            List<VaultObjectRevisionBlob> blobReferences,
            VaultObjectSignatureVerificationResponse signatureVerification,
            String signedByEmail
    ) {
        Base64.Encoder encoder = Base64.getEncoder();

        return new VaultObjectSnapshotResponse(
                object.getObjectId(),
                object.getCurrentVersion(),
                object.isDeleted(),
                object.getUpdatedAt(),

                revision.getRevisionId(),
                encoder.encodeToString(revision.getCiphertext()),
                revision.getContentAeadParams(),
                encoder.encodeToString(revision.getWrappedRecordKey()),
                revision.getRecordKeyWrapParams(),
                revision.getRecordKeyWrappedByVaultKeyVersion(),
                encoder.encodeToString(revision.getEncryptedPackageHash()),
                encoder.encodeToString(revision.getClientSignature()),
                revision.getSignatureFormatVersion(),
                revision.getSignatureKeyVersion(),
                signatureVerification,
                revision.getSignedByUserId(),
                signedByEmail,
                revision.getCreatedAt(),
                toBlobReferenceResponses(blobReferences)
        );
    }

    public VaultObjectRevisionResponse toRevisionResponse(
            VaultObjectRevision revision,
            List<VaultObjectRevisionBlob> blobReferences,
            VaultObjectSignatureVerificationResponse signatureVerification,
            String signedByEmail
    ) {
        Base64.Encoder encoder = Base64.getEncoder();

        return new VaultObjectRevisionResponse(
                revision.getRevisionId(),
                revision.getObjectId(),
                revision.getVersion(),
                encoder.encodeToString(revision.getCiphertext()),
                revision.getContentAeadParams(),
                encoder.encodeToString(revision.getWrappedRecordKey()),
                revision.getRecordKeyWrapParams(),
                revision.getRecordKeyWrappedByVaultKeyVersion(),
                encoder.encodeToString(revision.getEncryptedPackageHash()),
                encoder.encodeToString(revision.getClientSignature()),
                revision.getSignatureFormatVersion(),
                revision.getSignatureKeyVersion(),
                signatureVerification,
                revision.getSignedByUserId(),
                signedByEmail,
                revision.getCreatedAt(),
                toBlobReferenceResponses(blobReferences)
        );
    }

    private List<VaultBlobReferenceResponse> toBlobReferenceResponses(
            List<VaultObjectRevisionBlob> blobReferences
    ) {
        return blobReferences.stream()
                .map(reference -> new VaultBlobReferenceResponse(
                        reference.getBlobId(),
                        reference.getId().getRole()
                ))
                .toList();
    }
}
