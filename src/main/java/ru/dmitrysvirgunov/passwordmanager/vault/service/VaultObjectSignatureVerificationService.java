package ru.dmitrysvirgunov.passwordmanager.vault.service;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import ru.dmitrysvirgunov.passwordmanager.auth.entity.UserKeyMaterial;
import ru.dmitrysvirgunov.passwordmanager.auth.entity.UserKeyMaterialHistory;
import ru.dmitrysvirgunov.passwordmanager.auth.repository.UserKeyMaterialHistoryRepository;
import ru.dmitrysvirgunov.passwordmanager.auth.repository.UserKeyMaterialRepository;
import ru.dmitrysvirgunov.passwordmanager.common.exception.ConflictException;
import ru.dmitrysvirgunov.passwordmanager.common.exception.InvalidRequestException;
import ru.dmitrysvirgunov.passwordmanager.common.exception.ResourceNotFoundException;
import ru.dmitrysvirgunov.passwordmanager.vault.dto.response.object.VaultObjectSignatureKeySource;
import ru.dmitrysvirgunov.passwordmanager.vault.dto.response.object.VaultObjectSignatureVerificationResponse;
import ru.dmitrysvirgunov.passwordmanager.vault.dto.response.object.VaultObjectSignatureVerificationStatus;
import ru.dmitrysvirgunov.passwordmanager.vault.entity.VaultObjectRevision;
import ru.dmitrysvirgunov.passwordmanager.vault.model.BlobReferenceInput;

import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class VaultObjectSignatureVerificationService {

    private final UserKeyMaterialRepository userKeyMaterialRepository;
    private final UserKeyMaterialHistoryRepository userKeyMaterialHistoryRepository;

    public void verifyWritablePayload(UUID actorUserId, VaultObjectSignaturePayload payload) {
        if (payload.signatureFormatVersion() != VaultObjectSignatureV2.FORMAT_VERSION) {
            throw new InvalidRequestException(
                    "Unsupported vault object signature format version " + payload.signatureFormatVersion()
            );
        }

        UserKeyMaterial keyMaterial = userKeyMaterialRepository.findById(actorUserId)
                .orElseThrow(() -> new ResourceNotFoundException("User key material not found"));

        if (payload.signatureKeyVersion() != keyMaterial.getSigningKeyVersion()) {
            throw new ConflictException(
                    "Signing key version conflict: expected " + keyMaterial.getSigningKeyVersion()
                            + ", but request uses " + payload.signatureKeyVersion()
            );
        }

        byte[] canonicalBytes = VaultObjectSignatureV2.buildCanonicalBytes(payload);
        byte[] expectedHash = sha256(canonicalBytes);

        if (!Arrays.equals(expectedHash, payload.encryptedPackageHash())) {
            throw new InvalidRequestException("Vault object package hash mismatch");
        }

        PublicKey publicSigningKey = decodePublicSigningKey(keyMaterial.getPublicSigningKey());
        if (!verify(publicSigningKey, expectedHash, payload.clientSignature())) {
            throw new InvalidRequestException("Vault object signature verification failed");
        }
    }

    public VaultObjectSignatureVerificationResponse verifyRevision(
            VaultObjectRevision revision,
            List<BlobReferenceInput> blobReferences
    ) {
        if (revision.getSignatureFormatVersion() == 1) {
            return new VaultObjectSignatureVerificationResponse(
                    VaultObjectSignatureVerificationStatus.LEGACY_UNVERIFIED,
                    VaultObjectSignatureKeySource.NONE
            );
        }

        if (revision.getSignatureFormatVersion() != VaultObjectSignatureV2.FORMAT_VERSION) {
            return new VaultObjectSignatureVerificationResponse(
                    VaultObjectSignatureVerificationStatus.UNSUPPORTED_FORMAT,
                    VaultObjectSignatureKeySource.NONE
            );
        }

        byte[] expectedHash = sha256(VaultObjectSignatureV2.buildCanonicalBytes(
                new VaultObjectSignaturePayload(
                        revision.getCiphertext(),
                        revision.getContentAeadParams(),
                        revision.getWrappedRecordKey(),
                        revision.getRecordKeyWrapParams(),
                        revision.getEncryptedPackageHash(),
                        revision.getClientSignature(),
                        revision.getSignatureKeyVersion(),
                        revision.getSignatureFormatVersion(),
                        blobReferences
                )
        ));

        if (!Arrays.equals(expectedHash, revision.getEncryptedPackageHash())) {
            return new VaultObjectSignatureVerificationResponse(
                    VaultObjectSignatureVerificationStatus.HASH_MISMATCH,
                    VaultObjectSignatureKeySource.NONE
            );
        }

        VerificationKeyResolution keyResolution = resolveVerificationKey(
                revision.getSignedByUserId(),
                revision.getSignatureKeyVersion()
        );

        if (keyResolution == null) {
            return new VaultObjectSignatureVerificationResponse(
                    VaultObjectSignatureVerificationStatus.KEY_NOT_FOUND,
                    VaultObjectSignatureKeySource.NONE
            );
        }

        if (!verify(keyResolution.publicKey(), expectedHash, revision.getClientSignature())) {
            return new VaultObjectSignatureVerificationResponse(
                    VaultObjectSignatureVerificationStatus.SIGNATURE_INVALID,
                    keyResolution.keySource()
            );
        }

        return new VaultObjectSignatureVerificationResponse(
                VaultObjectSignatureVerificationStatus.VERIFIED,
                keyResolution.keySource()
        );
    }

    private byte[] sha256(byte[] bytes) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(bytes);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to hash vault object signature payload", e);
        }
    }

    private PublicKey decodePublicSigningKey(byte[] encodedPublicKey) {
        try {
            return KeyFactory.getInstance("Ed25519")
                    .generatePublic(new X509EncodedKeySpec(encodedPublicKey));
        } catch (Exception e) {
            throw new IllegalStateException("Failed to decode user public signing key", e);
        }
    }

    private boolean verify(PublicKey publicKey, byte[] payloadHash, byte[] signatureBytes) {
        try {
            Signature signature = Signature.getInstance("Ed25519");
            signature.initVerify(publicKey);
            signature.update(payloadHash);
            try {
                return signature.verify(signatureBytes);
            } catch (SignatureException | IllegalArgumentException e) {
                return false;
            }
        } catch (Exception e) {
            throw new IllegalStateException("Failed to verify vault object signature", e);
        }
    }

    private VerificationKeyResolution resolveVerificationKey(UUID userId, int signingKeyVersion) {
        if (userId == null) {
            return null;
        }

        Optional<UserKeyMaterial> currentKeyMaterial = userKeyMaterialRepository.findById(userId);
        if (currentKeyMaterial.isPresent()
                && currentKeyMaterial.get().getSigningKeyVersion() == signingKeyVersion) {
            return new VerificationKeyResolution(
                    decodePublicSigningKey(currentKeyMaterial.get().getPublicSigningKey()),
                    VaultObjectSignatureKeySource.CURRENT
            );
        }

        Optional<UserKeyMaterialHistory> historicalKeyMaterial = userKeyMaterialHistoryRepository
                .findTopByUserIdAndSigningKeyVersionOrderByArchivedAtDesc(userId, signingKeyVersion);

        if (historicalKeyMaterial.isEmpty()) {
            return null;
        }

        return new VerificationKeyResolution(
                decodePublicSigningKey(historicalKeyMaterial.get().getPublicSigningKey()),
                VaultObjectSignatureKeySource.HISTORY
        );
    }

    private record VerificationKeyResolution(
            PublicKey publicKey,
            VaultObjectSignatureKeySource keySource
    ) {
    }
}
