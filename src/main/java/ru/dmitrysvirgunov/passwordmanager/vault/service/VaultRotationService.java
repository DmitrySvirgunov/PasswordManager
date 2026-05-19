package ru.dmitrysvirgunov.passwordmanager.vault.service;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ru.dmitrysvirgunov.passwordmanager.audit.service.AuditService;
import ru.dmitrysvirgunov.passwordmanager.auth.entity.UserKeyMaterial;
import ru.dmitrysvirgunov.passwordmanager.auth.repository.UserKeyMaterialRepository;
import ru.dmitrysvirgunov.passwordmanager.common.exception.ConflictException;
import ru.dmitrysvirgunov.passwordmanager.common.exception.InvalidRequestException;
import ru.dmitrysvirgunov.passwordmanager.common.exception.ResourceNotFoundException;
import ru.dmitrysvirgunov.passwordmanager.common.model.AeadParams;
import ru.dmitrysvirgunov.passwordmanager.vault.dto.response.command.RotateRecordKeyResponse;
import ru.dmitrysvirgunov.passwordmanager.vault.dto.response.command.RotateVaultKeyResponse;
import ru.dmitrysvirgunov.passwordmanager.vault.entity.Vault;
import ru.dmitrysvirgunov.passwordmanager.vault.entity.VaultKeyEnvelope;
import ru.dmitrysvirgunov.passwordmanager.vault.entity.VaultMember;
import ru.dmitrysvirgunov.passwordmanager.vault.entity.VaultObject;
import ru.dmitrysvirgunov.passwordmanager.vault.entity.VaultObjectRevision;
import ru.dmitrysvirgunov.passwordmanager.vault.entity.VaultObjectRevisionBlob;
import ru.dmitrysvirgunov.passwordmanager.vault.entity.VaultObjectRevisionBlobId;
import ru.dmitrysvirgunov.passwordmanager.vault.model.*;
import ru.dmitrysvirgunov.passwordmanager.vault.repository.VaultKeyEnvelopeRepository;
import ru.dmitrysvirgunov.passwordmanager.vault.repository.VaultMemberRepository;
import ru.dmitrysvirgunov.passwordmanager.vault.repository.VaultObjectRepository;
import ru.dmitrysvirgunov.passwordmanager.vault.repository.VaultObjectRevisionBlobRepository;
import ru.dmitrysvirgunov.passwordmanager.vault.repository.VaultObjectRevisionRepository;
import ru.dmitrysvirgunov.passwordmanager.vault.repository.VaultRepository;
import tools.jackson.databind.JsonNode;

import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class VaultRotationService {

    private static final int CURRENT_ENVELOPE_VERSION = 1;

    private final VaultRepository vaultRepository;
    private final VaultMemberRepository vaultMemberRepository;
    private final VaultObjectRepository vaultObjectRepository;
    private final VaultObjectRevisionRepository vaultObjectRevisionRepository;
    private final VaultObjectRevisionBlobRepository vaultObjectRevisionBlobRepository;
    private final VaultKeyEnvelopeRepository vaultKeyEnvelopeRepository;
    private final UserKeyMaterialRepository userKeyMaterialRepository;
    private final VaultAccessService vaultAccessService;
    private final VaultSyncService vaultSyncService;
    private final AuditService auditService;
    private final VaultBlobService vaultBlobService;
    private final VaultObjectSignatureVerificationService vaultObjectSignatureVerificationService;

    @Transactional
    public RotateVaultKeyResponse rotateVaultKey(
            UUID vaultId,
            RotateVaultKeyInput input,
            UUID currentUserId
    ) {
        OffsetDateTime now = OffsetDateTime.now();

        Vault vault = loadVaultForUpdateOrThrow(vaultId);
        vaultAccessService.requireOwnerMembership(vaultId, currentUserId, now);

        validateVaultKeyVersionTransition(vault, input);

        List<VaultMember> activeMembers = loadActiveMembers(vaultId);
        Map<UUID, UserKeyMaterial> keyMaterialsByUserId = loadKeyMaterials(activeMembers);

        Map<UUID, RotateVaultKeyEnvelopeInput> envelopesByRecipient = indexEnvelopeInputs(input.envelopes());
        validateEnvelopeInputs(activeMembers, keyMaterialsByUserId, envelopesByRecipient);

        List<VaultObject> activeObjects = vaultObjectRepository.findActiveByVaultIdForUpdate(vaultId);
        Map<UUID, RotateVaultObjectInput> objectInputsById = indexObjectInputs(input.objects());
        validateRotateObjectInputs(activeObjects, objectInputsById);
        verifyRotateObjectSignatures(currentUserId, activeObjects, objectInputsById);

        List<VaultKeyEnvelope> newEnvelopes = buildNewEnvelopes(
                vaultId,
                currentUserId,
                input.newVaultKeyVersion(),
                envelopesByRecipient,
                now
        );

        List<VaultObjectRevision> newRevisions = new ArrayList<>();
        List<VaultObjectRevisionBlob> newRevisionBlobReferences = new ArrayList<>();
        List<VaultObject> updatedObjects = new ArrayList<>();

        for (VaultObject object : activeObjects) {
            RotateVaultObjectInput objectInput = objectInputsById.get(object.getObjectId());
            int newVersion = object.getCurrentVersion() + 1;
            UUID revisionId = UUID.randomUUID();

            VaultObjectRevision revision = VaultObjectRevision.builder()
                    .revisionId(revisionId)
                    .objectId(object.getObjectId())
                    .version(newVersion)
                    .ciphertext(objectInput.ciphertext())
                    .contentAeadParams(objectInput.contentAeadParams())
                    .wrappedRecordKey(objectInput.wrappedRecordKey())
                    .recordKeyWrapParams(objectInput.recordKeyWrapParams())
                    .recordKeyWrappedByVaultKeyVersion(input.newVaultKeyVersion())
                    .encryptedPackageHash(objectInput.encryptedPackageHash())
                    .clientSignature(objectInput.clientSignature())
                    .signatureFormatVersion(objectInput.signatureFormatVersion())
                    .signatureKeyVersion(objectInput.signatureKeyVersion())
                    .signedByUserId(currentUserId)
                    .createdAt(now)
                    .build();

            object.setCurrentVersion(newVersion);
            object.setUpdatedAt(now);

            newRevisions.add(revision);
            updatedObjects.add(object);
            newRevisionBlobReferences.addAll(
                    buildBlobReferences(revisionId, objectInput.blobReferences(), now)
            );
        }

        int previousVaultKeyVersion = vault.getCurrentVaultKeyVersion();

        vault.setNameCiphertext(input.nameCiphertext());
        vault.setNameAeadParams(input.nameAeadParams());
        vault.setCurrentVaultKeyVersion(input.newVaultKeyVersion());
        vault.setUpdatedAt(now);

        vaultRepository.save(vault);
        vaultKeyEnvelopeRepository.saveAll(newEnvelopes);
        vaultObjectRevisionRepository.saveAll(newRevisions);
        vaultObjectRevisionBlobRepository.saveAll(newRevisionBlobReferences);
        vaultObjectRepository.saveAll(updatedObjects);

        vaultSyncService.appendRotateVaultKey(vaultId, currentUserId, now);

        for (VaultObject object : updatedObjects) {
            vaultSyncService.appendUpsert(
                    vaultId,
                    object.getObjectId(),
                    object.getCurrentVersion(),
                    currentUserId,
                    now
            );
        }

        auditService.appendVaultKeyRotated(
                currentUserId,
                vaultId,
                previousVaultKeyVersion,
                input.newVaultKeyVersion(),
                updatedObjects.size(),
                now
        );

        return new RotateVaultKeyResponse(
                vaultId,
                previousVaultKeyVersion,
                input.newVaultKeyVersion(),
                updatedObjects.size(),
                now
        );
    }

    //TODO: метод не протестирован
    @Transactional
    public RotateRecordKeyResponse rotateRecordKey(
            UUID vaultId,
            UUID objectId,
            RotateRecordKeyInput input,
            UUID currentUserId
    ) {
        OffsetDateTime now = OffsetDateTime.now();

        Vault vault = loadVaultForUpdateOrThrow(vaultId);

        vaultAccessService.requireWritableMembership(vaultId, currentUserId, now);

        VaultObject object = loadActiveObjectForUpdateOrThrow(vaultId, objectId);

        validateRotateRecordKeyInput(vault, object, input);

        int previousVersion = object.getCurrentVersion();
        int newVersion = previousVersion + 1;

        VaultObjectRevision revision = buildNewRevision(
                object.getObjectId(),
                newVersion,
                input.ciphertext(),
                input.contentAeadParams(),
                input.wrappedRecordKey(),
                input.recordKeyWrapParams(),
                vault.getCurrentVaultKeyVersion(),
                input.encryptedPackageHash(),
                input.clientSignature(),
                input.signatureFormatVersion(),
                input.signatureKeyVersion(),
                currentUserId,
                now
        );

        object.setCurrentVersion(newVersion);
        object.setUpdatedAt(now);

        vaultObjectRevisionRepository.save(revision);
        vaultObjectRepository.save(object);

        vaultSyncService.appendUpsert(
                vaultId,
                objectId,
                newVersion,
                currentUserId,
                now
        );

        auditService.appendRecordKeyRotated(
                currentUserId,
                vaultId,
                objectId,
                previousVersion,
                newVersion,
                vault.getCurrentVaultKeyVersion(),
                now
        );

        return new RotateRecordKeyResponse(
                vaultId,
                objectId,
                previousVersion,
                newVersion,
                vault.getCurrentVaultKeyVersion(),
                now
        );
    }

    private Vault loadVaultForUpdateOrThrow(UUID vaultId) {
        return vaultRepository.findByVaultIdForUpdate(vaultId)
                .orElseThrow(() -> new ResourceNotFoundException("Vault not found"));
    }

    private void validateVaultKeyVersionTransition(Vault vault, RotateVaultKeyInput input) {
        if (input.expectedCurrentVaultKeyVersion() != vault.getCurrentVaultKeyVersion()) {
            throw new ConflictException(
                    "Vault key version conflict: expected " + input.expectedCurrentVaultKeyVersion()
                            + ", but current version is " + vault.getCurrentVaultKeyVersion()
            );
        }

        if (input.newVaultKeyVersion() != vault.getCurrentVaultKeyVersion() + 1) {
            throw new InvalidRequestException(
                    "newVaultKeyVersion must be exactly currentVaultKeyVersion + 1"
            );
        }
    }

    private List<VaultMember> loadActiveMembers(UUID vaultId) {
        return vaultMemberRepository.findByIdVaultIdAndStatusAndRevokedAtIsNullOrderByJoinedAtAsc(
                vaultId,
                VaultMemberStatus.ACTIVE
        );
    }

    private Map<UUID, UserKeyMaterial> loadKeyMaterials(List<VaultMember> activeMembers) {
        List<UUID> userIds = activeMembers.stream()
                .map(member -> member.getId().getUserId())
                .toList();

        return userKeyMaterialRepository.findAllById(userIds).stream()
                .collect(Collectors.toMap(
                        UserKeyMaterial::getUserId,
                        Function.identity()
                ));
    }

    private Map<UUID, RotateVaultKeyEnvelopeInput> indexEnvelopeInputs(
            List<RotateVaultKeyEnvelopeInput> envelopeInputs
    ) {
        Map<UUID, RotateVaultKeyEnvelopeInput> indexed = new LinkedHashMap<>();

        for (RotateVaultKeyEnvelopeInput envelopeInput : envelopeInputs) {
            RotateVaultKeyEnvelopeInput previous = indexed.put(envelopeInput.recipientUserId(), envelopeInput);
            if (previous != null) {
                throw new InvalidRequestException(
                        "Duplicate rotate envelope for recipientUserId " + envelopeInput.recipientUserId()
                );
            }
        }

        return indexed;
    }

    private void validateEnvelopeInputs(
            List<VaultMember> activeMembers,
            Map<UUID, UserKeyMaterial> keyMaterialsByUserId,
            Map<UUID, RotateVaultKeyEnvelopeInput> envelopesByRecipient
    ) {
        if (activeMembers.size() != envelopesByRecipient.size()) {
            throw new InvalidRequestException(
                    "Rotate request must contain exactly one envelope for each ACTIVE vault member"
            );
        }

        for (VaultMember member : activeMembers) {
            UUID userId = member.getId().getUserId();

            RotateVaultKeyEnvelopeInput envelopeInput = envelopesByRecipient.get(userId);
            if (envelopeInput == null) {
                throw new InvalidRequestException(
                        "Missing rotate envelope for active member " + userId
                );
            }

            UserKeyMaterial keyMaterial = keyMaterialsByUserId.get(userId);
            if (keyMaterial == null) {
                throw new ResourceNotFoundException(
                        "User key material not found for active member " + userId
                );
            }

            if (envelopeInput.recipientEncryptionKeyVersion() != keyMaterial.getEncryptionKeyVersion()) {
                throw new ConflictException(
                        "recipientEncryptionKeyVersion does not match current key version for user " + userId
                );
            }
        }
    }

    private Map<UUID, RotateVaultObjectInput> indexObjectInputs(
            List<RotateVaultObjectInput> objectInputs
    ) {
        Map<UUID, RotateVaultObjectInput> indexed = new LinkedHashMap<>();

        for (RotateVaultObjectInput objectInput : objectInputs) {
            RotateVaultObjectInput previous = indexed.put(objectInput.objectId(), objectInput);
            if (previous != null) {
                throw new InvalidRequestException(
                        "Duplicate rotate object payload for objectId " + objectInput.objectId()
                );
            }
        }

        return indexed;
    }

    private void validateRotateObjectInputs(
            List<VaultObject> activeObjects,
            Map<UUID, RotateVaultObjectInput> objectInputsById
    ) {
        if (activeObjects.size() != objectInputsById.size()) {
            throw new InvalidRequestException(
                    "Rotate request must contain exactly one rotate payload for each non-deleted current object"
            );
        }

        for (VaultObject object : activeObjects) {
            RotateVaultObjectInput objectInput = objectInputsById.get(object.getObjectId());
            if (objectInput == null) {
                throw new InvalidRequestException(
                        "Missing rotate payload for objectId " + object.getObjectId()
                );
            }

            if (objectInput.expectedCurrentVersion() != object.getCurrentVersion()) {
                throw new ConflictException(
                        "Object version conflict during rotate for objectId " + object.getObjectId()
                                + ": expected " + objectInput.expectedCurrentVersion()
                                + ", but current version is " + object.getCurrentVersion()
                );
            }

            validateBlobReferences(vaultIdFor(object), objectInput.blobReferences());
        }
    }

    private List<VaultKeyEnvelope> buildNewEnvelopes(
            UUID vaultId,
            UUID currentUserId,
            int newVaultKeyVersion,
            Map<UUID, RotateVaultKeyEnvelopeInput> envelopesByRecipient,
            OffsetDateTime now
    ) {
        List<VaultKeyEnvelope> envelopes = new ArrayList<>();

        for (RotateVaultKeyEnvelopeInput envelopeInput : envelopesByRecipient.values()) {
            VaultKeyEnvelope envelope = VaultKeyEnvelope.builder()
                    .envelopeId(UUID.randomUUID())
                    .vaultId(vaultId)
                    .vaultKeyVersion(newVaultKeyVersion)
                    .recipientUserId(envelopeInput.recipientUserId())
                    .recipientEncryptionKeyVersion(envelopeInput.recipientEncryptionKeyVersion())
                    .envelopeVersion(CURRENT_ENVELOPE_VERSION)
                    .encryptedVaultKey(envelopeInput.encryptedVaultKey())
                    .envelopeParams(envelopeInput.envelopeParams())
                    .createdByUserId(currentUserId)
                    .createdAt(now)
                    .revokedAt(null)
                    .build();

            envelopes.add(envelope);
        }

        return envelopes;
    }

    private VaultObject loadActiveObjectForUpdateOrThrow(UUID vaultId, UUID objectId) {
        return vaultObjectRepository.findForUpdate(objectId, vaultId)
                .orElseThrow(() -> new ResourceNotFoundException("Vault object not found"));
    }

    private void validateRotateRecordKeyInput(
            Vault vault,
            VaultObject object,
            RotateRecordKeyInput input
    ) {
        if (input.expectedCurrentVersion() != object.getCurrentVersion()) {
            throw new ConflictException(
                    "Object version conflict: expected " + input.expectedCurrentVersion()
                            + ", but current version is " + object.getCurrentVersion()
            );
        }

        if (input.expectedCurrentVaultKeyVersion() != vault.getCurrentVaultKeyVersion()) {
            throw new ConflictException(
                    "Vault key version conflict: expected " + input.expectedCurrentVaultKeyVersion()
                            + ", but current version is " + vault.getCurrentVaultKeyVersion()
            );
        }
    }

    private void verifyRotateObjectSignatures(
            UUID currentUserId,
            List<VaultObject> activeObjects,
            Map<UUID, RotateVaultObjectInput> objectInputsById
    ) {
        for (VaultObject object : activeObjects) {
            RotateVaultObjectInput objectInput = objectInputsById.get(object.getObjectId());

            vaultObjectSignatureVerificationService.verifyWritablePayload(
                    currentUserId,
                    new VaultObjectSignaturePayload(
                            objectInput.ciphertext(),
                            objectInput.contentAeadParams(),
                            objectInput.wrappedRecordKey(),
                            objectInput.recordKeyWrapParams(),
                            objectInput.encryptedPackageHash(),
                            objectInput.clientSignature(),
                            objectInput.signatureKeyVersion(),
                            objectInput.signatureFormatVersion(),
                            objectInput.blobReferences()
                    )
            );
        }
    }

    private void validateBlobReferences(UUID vaultId, List<BlobReferenceInput> blobReferences) {
        java.util.Set<UUID> blobIds = new java.util.HashSet<>();
        java.util.Set<Object> roles = new java.util.HashSet<>();

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

            vaultBlobService.requireReadyBlobForReference(vaultId, blobReference.blobId());
        }
    }

    private List<VaultObjectRevisionBlob> buildBlobReferences(
            UUID revisionId,
            List<BlobReferenceInput> blobReferences,
            OffsetDateTime now
    ) {
        if (blobReferences.isEmpty()) {
            return List.of();
        }

        return blobReferences.stream()
                .map(blobReference -> VaultObjectRevisionBlob.builder()
                        .id(new VaultObjectRevisionBlobId(revisionId, blobReference.role()))
                        .blobId(blobReference.blobId())
                        .createdAt(now)
                        .build())
                .toList();
    }

    private UUID vaultIdFor(VaultObject object) {
        return object.getVaultId();
    }

    private VaultObjectRevision buildNewRevision(
            UUID objectId,
            int version,
            byte[] ciphertext,
            AeadParams contentAeadParams,
            byte[] wrappedRecordKey,
            JsonNode recordKeyWrapParams,
            int recordKeyWrappedByVaultKeyVersion,
            byte[] encryptedPackageHash,
            byte[] clientSignature,
            int signatureFormatVersion,
            int signatureKeyVersion,
            UUID signedByUserId,
            OffsetDateTime createdAt
    ) {
        return VaultObjectRevision.builder()
                .revisionId(UUID.randomUUID())
                .objectId(objectId)
                .version(version)
                .ciphertext(ciphertext)
                .contentAeadParams(contentAeadParams)
                .wrappedRecordKey(wrappedRecordKey)
                .recordKeyWrapParams(recordKeyWrapParams)
                .recordKeyWrappedByVaultKeyVersion(recordKeyWrappedByVaultKeyVersion)
                .encryptedPackageHash(encryptedPackageHash)
                .clientSignature(clientSignature)
                .signatureFormatVersion(signatureFormatVersion)
                .signatureKeyVersion(signatureKeyVersion)
                .signedByUserId(signedByUserId)
                .createdAt(createdAt)
                .build();
    }
}
