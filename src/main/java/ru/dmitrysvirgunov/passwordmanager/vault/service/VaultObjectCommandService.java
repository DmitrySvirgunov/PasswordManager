package ru.dmitrysvirgunov.passwordmanager.vault.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ru.dmitrysvirgunov.passwordmanager.audit.service.AuditService;
import ru.dmitrysvirgunov.passwordmanager.common.exception.ConflictException;
import ru.dmitrysvirgunov.passwordmanager.common.exception.ResourceNotFoundException;
import ru.dmitrysvirgunov.passwordmanager.vault.dto.response.command.CreateVaultObjectResponse;
import ru.dmitrysvirgunov.passwordmanager.vault.dto.response.command.DeleteVaultObjectResponse;
import ru.dmitrysvirgunov.passwordmanager.vault.dto.response.command.UpdateVaultObjectResponse;
import ru.dmitrysvirgunov.passwordmanager.vault.entity.Vault;
import ru.dmitrysvirgunov.passwordmanager.vault.entity.VaultBlob;
import ru.dmitrysvirgunov.passwordmanager.vault.entity.VaultObject;
import ru.dmitrysvirgunov.passwordmanager.vault.entity.VaultObjectRevision;
import ru.dmitrysvirgunov.passwordmanager.vault.entity.VaultObjectRevisionBlob;
import ru.dmitrysvirgunov.passwordmanager.vault.entity.VaultObjectRevisionBlobId;
import ru.dmitrysvirgunov.passwordmanager.vault.model.BlobReferenceInput;
import ru.dmitrysvirgunov.passwordmanager.vault.model.CreateVaultObjectInput;
import ru.dmitrysvirgunov.passwordmanager.vault.model.DeleteVaultObjectInput;
import ru.dmitrysvirgunov.passwordmanager.vault.model.UpdateVaultObjectInput;
import ru.dmitrysvirgunov.passwordmanager.vault.repository.VaultObjectRepository;
import ru.dmitrysvirgunov.passwordmanager.vault.repository.VaultObjectRevisionBlobRepository;
import ru.dmitrysvirgunov.passwordmanager.vault.repository.VaultObjectRevisionRepository;
import ru.dmitrysvirgunov.passwordmanager.vault.repository.VaultRepository;

import java.time.OffsetDateTime;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class VaultObjectCommandService {

    private static final int INITIAL_OBJECT_VERSION = 1;

    private final VaultRepository vaultRepository;
    private final VaultObjectRepository vaultObjectRepository;
    private final VaultObjectRevisionRepository vaultObjectRevisionRepository;
    private final VaultObjectRevisionBlobRepository vaultObjectRevisionBlobRepository;
    private final VaultAccessService vaultAccessService;
    private final VaultSyncService vaultSyncService;
    private final AuditService auditService;
    private final VaultBlobService vaultBlobService;
    private final VaultObjectSignatureVerificationService vaultObjectSignatureVerificationService;

    @Transactional
    public CreateVaultObjectResponse createObject(UUID vaultId, CreateVaultObjectInput input, Jwt jwt) {
        UUID currentUserId = UUID.fromString(jwt.getSubject());
        OffsetDateTime now = OffsetDateTime.now();

        Vault vault = loadVaultOrThrow(vaultId);
        vaultAccessService.requireWritableMembership(vaultId, currentUserId, now);
        validateBlobReferences(vaultId, input.blobReferences());
        verifyObjectSignature(currentUserId, input);

        UUID objectId = UUID.randomUUID();
        UUID revisionId = UUID.randomUUID();

        VaultObject vaultObject = VaultObject.builder()
                .objectId(objectId)
                .vaultId(vaultId)
                .currentVersion(INITIAL_OBJECT_VERSION)
                .deleted(false)
                .createdAt(now)
                .updatedAt(now)
                .build();

        VaultObjectRevision revision = VaultObjectRevision.builder()
                .revisionId(revisionId)
                .objectId(objectId)
                .version(INITIAL_OBJECT_VERSION)
                .ciphertext(input.ciphertext())
                .contentAeadParams(input.contentAeadParams())
                .wrappedRecordKey(input.wrappedRecordKey())
                .recordKeyWrapParams(input.recordKeyWrapParams())
                .recordKeyWrappedByVaultKeyVersion(vault.getCurrentVaultKeyVersion())
                .encryptedPackageHash(input.encryptedPackageHash())
                .clientSignature(input.clientSignature())
                .signatureFormatVersion(input.signatureFormatVersion())
                .signatureKeyVersion(input.signatureKeyVersion())
                .signedByUserId(currentUserId)
                .createdAt(now)
                .build();

        vaultObjectRepository.save(vaultObject);
        vaultObjectRevisionRepository.save(revision);
        saveBlobReferences(revisionId, input.blobReferences(), now);

        vaultSyncService.appendUpsert(
                vaultId,
                objectId,
                INITIAL_OBJECT_VERSION,
                currentUserId,
                now
        );

        auditService.appendObjectCreated(
                currentUserId,
                vaultId,
                objectId,
                INITIAL_OBJECT_VERSION,
                now
        );

        return new CreateVaultObjectResponse(
                objectId,
                revisionId,
                INITIAL_OBJECT_VERSION,
                now
        );
    }

    // Инвариант безопасности:
    // каждая новая ревизия объекта должна создаваться клиентом с новым recordKey.
    // Бэкенд сохраняет новый wrappedRecordKey и новый ciphertext,
    // но не может криптографически проверить, что recordKey действительно новый.
    @Transactional
    public UpdateVaultObjectResponse updateObject(
            UUID vaultId,
            UUID objectId,
            UpdateVaultObjectInput input,
            Jwt jwt
    ) {
        UUID currentUserId = UUID.fromString(jwt.getSubject());
        OffsetDateTime now = OffsetDateTime.now();

        Vault vault = loadVaultOrThrow(vaultId);
        vaultAccessService.requireWritableMembership(vaultId, currentUserId, now);

        VaultObject vaultObject = vaultObjectRepository.findForUpdate(objectId, vaultId)
                .orElseThrow(() -> new ResourceNotFoundException("Vault object not found"));

        if (vaultObject.isDeleted()) {
            throw new ResourceNotFoundException("Vault object not found");
        }

        validateUpdatableObject(vaultObject, input.expectedVersion());
        validateCurrentVaultKeyVersion(vault, input.expectedCurrentVaultKeyVersion());
        validateBlobReferences(vaultId, input.blobReferences());
        verifyObjectSignature(currentUserId, input);

        int newVersion = vaultObject.getCurrentVersion() + 1;
        UUID revisionId = UUID.randomUUID();

        VaultObjectRevision revision = VaultObjectRevision.builder()
                .revisionId(revisionId)
                .objectId(objectId)
                .version(newVersion)
                .ciphertext(input.ciphertext())
                .contentAeadParams(input.contentAeadParams())
                .wrappedRecordKey(input.wrappedRecordKey())
                .recordKeyWrapParams(input.recordKeyWrapParams())
                .recordKeyWrappedByVaultKeyVersion(vault.getCurrentVaultKeyVersion())
                .encryptedPackageHash(input.encryptedPackageHash())
                .clientSignature(input.clientSignature())
                .signatureFormatVersion(input.signatureFormatVersion())
                .signatureKeyVersion(input.signatureKeyVersion())
                .signedByUserId(currentUserId)
                .createdAt(now)
                .build();

        vaultObject.setCurrentVersion(newVersion);
        vaultObject.setUpdatedAt(now);

        vaultObjectRevisionRepository.save(revision);
        vaultObjectRepository.save(vaultObject);
        saveBlobReferences(revisionId, input.blobReferences(), now);

        vaultSyncService.appendUpsert(
                vaultId,
                objectId,
                newVersion,
                currentUserId,
                now
        );

        auditService.appendObjectUpdated(
                currentUserId,
                vaultId,
                objectId,
                newVersion,
                now
        );

        return new UpdateVaultObjectResponse(
                objectId,
                revisionId,
                newVersion,
                now
        );
    }

    @Transactional
    public DeleteVaultObjectResponse deleteObject(
            UUID vaultId,
            UUID objectId,
            DeleteVaultObjectInput input,
            Jwt jwt
    ) {
        UUID currentUserId = UUID.fromString(jwt.getSubject());
        OffsetDateTime now = OffsetDateTime.now();

        Vault vault = loadVaultOrThrow(vaultId);
        vaultAccessService.requireWritableMembership(vaultId, currentUserId, now);

        VaultObject vaultObject = vaultObjectRepository.findForUpdate(objectId, vaultId)
                .orElseThrow(() -> new ResourceNotFoundException("Vault object not found"));

        validateDeletableObject(vaultObject, input.expectedVersion());
        validateBlobReferences(vaultId, input.blobReferences());
        verifyObjectSignature(currentUserId, input);

        int newVersion = vaultObject.getCurrentVersion() + 1;
        UUID revisionId = UUID.randomUUID();

        VaultObjectRevision revision = VaultObjectRevision.builder()
                .revisionId(revisionId)
                .objectId(objectId)
                .version(newVersion)
                .ciphertext(input.ciphertext())
                .contentAeadParams(input.contentAeadParams())
                .wrappedRecordKey(input.wrappedRecordKey())
                .recordKeyWrapParams(input.recordKeyWrapParams())
                .recordKeyWrappedByVaultKeyVersion(vault.getCurrentVaultKeyVersion())
                .encryptedPackageHash(input.encryptedPackageHash())
                .clientSignature(input.clientSignature())
                .signatureFormatVersion(input.signatureFormatVersion())
                .signatureKeyVersion(input.signatureKeyVersion())
                .signedByUserId(currentUserId)
                .createdAt(now)
                .build();

        vaultObject.setCurrentVersion(newVersion);
        vaultObject.setDeleted(true);
        vaultObject.setUpdatedAt(now);

        vaultObjectRevisionRepository.save(revision);
        vaultObjectRepository.save(vaultObject);
        saveBlobReferences(revisionId, input.blobReferences(), now);

        vaultSyncService.appendDelete(
                vaultId,
                objectId,
                newVersion,
                currentUserId,
                now
        );

        auditService.appendObjectDeleted(
                currentUserId,
                vaultId,
                objectId,
                newVersion,
                now
        );

        return new DeleteVaultObjectResponse(
                objectId,
                revisionId,
                newVersion,
                now
        );
    }

    private Vault loadVaultOrThrow(UUID vaultId) {
        return vaultRepository.findById(vaultId)
                .orElseThrow(() -> new ResourceNotFoundException("Vault not found"));
    }

    private void validateUpdatableObject(VaultObject vaultObject, int expectedVersion) {
        if (vaultObject.isDeleted()) {
            throw new ConflictException("Vault object is deleted");
        }

        if (expectedVersion != vaultObject.getCurrentVersion()) {
            throw new ConflictException(
                    "Version conflict: expected " + expectedVersion
                            + ", but current version is " + vaultObject.getCurrentVersion()
            );
        }
    }

    private void validateDeletableObject(VaultObject vaultObject, int expectedVersion) {
        if (vaultObject.isDeleted()) {
            throw new ConflictException("Vault object is already deleted");
        }

        if (expectedVersion != vaultObject.getCurrentVersion()) {
            throw new ConflictException(
                    "Version conflict: expected " + expectedVersion
                            + ", but current version is " + vaultObject.getCurrentVersion()
            );
        }
    }

    private void validateCurrentVaultKeyVersion(Vault vault, int expectedCurrentVaultKeyVersion) {
        if (expectedCurrentVaultKeyVersion != vault.getCurrentVaultKeyVersion()) {
            throw new ConflictException(
                    "Vault key version conflict: expected " + expectedCurrentVaultKeyVersion
                            + ", but current version is " + vault.getCurrentVaultKeyVersion()
            );
        }
    }

    private void validateBlobReferences(UUID vaultId, List<BlobReferenceInput> blobReferences) {
        Set<UUID> blobIds = new HashSet<>();
        Set<Object> roles = new HashSet<>();

        List<BlobReferenceInput> sortedReferences = blobReferences.stream()
                .sorted(Comparator
                        .comparing(BlobReferenceInput::blobId)
                        .thenComparing(blobReference -> blobReference.role().name()))
                .toList();

        for (BlobReferenceInput blobReference : sortedReferences) {
            if (!blobIds.add(blobReference.blobId())) {
                throw new ConflictException(
                        "Duplicate blob reference for blobId " + blobReference.blobId()
                );
            }

            if (!roles.add(blobReference.role())) {
                throw new ConflictException(
                        "Duplicate blob reference role " + blobReference.role()
                );
            }

            VaultBlob blob = vaultBlobService.requireReadyBlobForReference(vaultId, blobReference.blobId());
            if (!blob.getVaultId().equals(vaultId)) {
                throw new ConflictException("Vault blob does not belong to this vault");
            }
        }
    }

    private void saveBlobReferences(UUID revisionId, List<BlobReferenceInput> blobReferences, OffsetDateTime now) {
        if (blobReferences.isEmpty()) {
            return;
        }

        List<VaultObjectRevisionBlob> references = blobReferences.stream()
                .map(blobReference -> VaultObjectRevisionBlob.builder()
                        .id(new VaultObjectRevisionBlobId(revisionId, blobReference.role()))
                        .blobId(blobReference.blobId())
                        .createdAt(now)
                        .build())
                .toList();

        vaultObjectRevisionBlobRepository.saveAll(references);
    }

    private void verifyObjectSignature(UUID currentUserId, CreateVaultObjectInput input) {
        vaultObjectSignatureVerificationService.verifyWritablePayload(
                currentUserId,
                new VaultObjectSignaturePayload(
                        input.ciphertext(),
                        input.contentAeadParams(),
                        input.wrappedRecordKey(),
                        input.recordKeyWrapParams(),
                        input.encryptedPackageHash(),
                        input.clientSignature(),
                        input.signatureKeyVersion(),
                        input.signatureFormatVersion(),
                        input.blobReferences()
                )
        );
    }

    private void verifyObjectSignature(UUID currentUserId, UpdateVaultObjectInput input) {
        vaultObjectSignatureVerificationService.verifyWritablePayload(
                currentUserId,
                new VaultObjectSignaturePayload(
                        input.ciphertext(),
                        input.contentAeadParams(),
                        input.wrappedRecordKey(),
                        input.recordKeyWrapParams(),
                        input.encryptedPackageHash(),
                        input.clientSignature(),
                        input.signatureKeyVersion(),
                        input.signatureFormatVersion(),
                        input.blobReferences()
                )
        );
    }

    private void verifyObjectSignature(UUID currentUserId, DeleteVaultObjectInput input) {
        vaultObjectSignatureVerificationService.verifyWritablePayload(
                currentUserId,
                new VaultObjectSignaturePayload(
                        input.ciphertext(),
                        input.contentAeadParams(),
                        input.wrappedRecordKey(),
                        input.recordKeyWrapParams(),
                        input.encryptedPackageHash(),
                        input.clientSignature(),
                        input.signatureKeyVersion(),
                        input.signatureFormatVersion(),
                        input.blobReferences()
                )
        );
    }
}
