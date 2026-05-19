package ru.dmitrysvirgunov.passwordmanager.audit.service;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ru.dmitrysvirgunov.passwordmanager.audit.entity.AuditEvent;
import ru.dmitrysvirgunov.passwordmanager.audit.entity.AuditScopeHead;
import ru.dmitrysvirgunov.passwordmanager.audit.entity.AuditScopeHeadId;
import ru.dmitrysvirgunov.passwordmanager.audit.model.AuditEventTypeCodes;
import ru.dmitrysvirgunov.passwordmanager.audit.model.AuditScopeType;
import ru.dmitrysvirgunov.passwordmanager.audit.repository.AuditEventRepository;
import ru.dmitrysvirgunov.passwordmanager.audit.repository.AuditScopeHeadRepository;
import ru.dmitrysvirgunov.passwordmanager.vault.model.VaultMemberRole;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.JsonNodeFactory;
import tools.jackson.databind.node.ObjectNode;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuditService {

    private final AuditEventRepository auditEventRepository;
    private final AuditSigningService auditSigningService;
    private final AuditCanonicalJsonService auditCanonicalJsonService;
    private final AuditHashService auditHashService;
    private final AuditScopeHeadRepository auditScopeHeadRepository;
    private final AuditScopeLockService auditScopeLockService;
    private final AuditAnchorService auditAnchorService;

    @Transactional
    public void appendUserRegistered(UUID userId, OffsetDateTime createdAt) {
        ObjectNode meta = JsonNodeFactory.instance.objectNode();
        meta.put("userId", userId.toString());

        append(
                userId,
                AuditScopeType.USER,
                userId,
                AuditEventTypeCodes.USER_REGISTERED,
                meta,
                createdAt
        );
    }

    @Transactional
    public void appendLoginSucceeded(UUID userId, OffsetDateTime createdAt) {
        appendSimpleUserEvent(userId, AuditEventTypeCodes.LOGIN_SUCCEEDED, createdAt);
    }

    @Transactional
    public void appendRefreshSucceeded(UUID userId, OffsetDateTime createdAt) {
        appendSimpleUserEvent(userId, AuditEventTypeCodes.REFRESH_SUCCEEDED, createdAt);
    }

    @Transactional
    public void appendLogoutSucceeded(UUID userId, OffsetDateTime createdAt) {
        appendSimpleUserEvent(userId, AuditEventTypeCodes.LOGOUT_SUCCEEDED, createdAt);
    }

    @Transactional
    public void appendPasswordChanged(UUID userId, OffsetDateTime createdAt) {
        appendSimpleUserEvent(userId, AuditEventTypeCodes.PASSWORD_CHANGED, createdAt);
    }

    @Transactional
    public void appendUserKeysRotated(
            UUID userId,
            int previousEncryptionKeyVersion,
            int newEncryptionKeyVersion,
            int previousSigningKeyVersion,
            int newSigningKeyVersion,
            int rotatedVaultCount,
            OffsetDateTime createdAt
    ) {
        ObjectNode meta = JsonNodeFactory.instance.objectNode();
        meta.put("userId", userId.toString());
        meta.put("previousEncryptionKeyVersion", previousEncryptionKeyVersion);
        meta.put("newEncryptionKeyVersion", newEncryptionKeyVersion);
        meta.put("previousSigningKeyVersion", previousSigningKeyVersion);
        meta.put("newSigningKeyVersion", newSigningKeyVersion);
        meta.put("rotatedVaultCount", rotatedVaultCount);

        append(
                userId,
                AuditScopeType.USER,
                userId,
                AuditEventTypeCodes.USER_KEYS_ROTATED,
                meta,
                createdAt
        );
    }

    @Transactional
    public void appendAccountDeleted(UUID userId, OffsetDateTime createdAt) {
        appendSimpleUserEvent(userId, AuditEventTypeCodes.ACCOUNT_DELETED, createdAt);
    }

    @Transactional
    public void appendVaultCreated(
            UUID actorUserId,
            UUID vaultId,
            int vaultVersion,
            OffsetDateTime createdAt
    ) {
        ObjectNode meta = JsonNodeFactory.instance.objectNode();
        meta.put("vaultId", vaultId.toString());
        meta.put("vaultVersion", vaultVersion);

        append(
                actorUserId,
                AuditScopeType.VAULT,
                vaultId,
                AuditEventTypeCodes.VAULT_CREATED,
                meta,
                createdAt
        );
    }

    @Transactional
    public void appendObjectCreated(
            UUID actorUserId,
            UUID vaultId,
            UUID objectId,
            int version,
            OffsetDateTime createdAt
    ) {
        appendObjectEvent(
                actorUserId,
                vaultId,
                AuditEventTypeCodes.OBJECT_CREATED,
                objectId,
                version,
                createdAt
        );
    }

    @Transactional
    public void appendObjectUpdated(
            UUID actorUserId,
            UUID vaultId,
            UUID objectId,
            int version,
            OffsetDateTime createdAt
    ) {
        appendObjectEvent(
                actorUserId,
                vaultId,
                AuditEventTypeCodes.OBJECT_UPDATED,
                objectId,
                version,
                createdAt
        );
    }

    @Transactional
    public void appendObjectDeleted(
            UUID actorUserId,
            UUID vaultId,
            UUID objectId,
            int version,
            OffsetDateTime createdAt
    ) {
        appendObjectEvent(
                actorUserId,
                vaultId,
                AuditEventTypeCodes.OBJECT_DELETED,
                objectId,
                version,
                createdAt
        );
    }

    @Transactional
    public void appendInviteCreated(
            UUID actorUserId,
            UUID vaultId,
            UUID inviteId,
            UUID inviteeUserId,
            String inviteeEmail,
            VaultMemberRole role,
            OffsetDateTime createdAt
    ) {
        ObjectNode meta = JsonNodeFactory.instance.objectNode();
        meta.put("inviteId", inviteId.toString());
        meta.put("inviteeUserId", inviteeUserId.toString());
        meta.put("inviteeEmail", inviteeEmail);
        meta.put("role", role.name());

        append(
                actorUserId,
                AuditScopeType.VAULT,
                vaultId,
                AuditEventTypeCodes.INVITE_CREATED,
                meta,
                createdAt
        );
    }

    @Transactional
    public void appendInviteRevoked(
            UUID actorUserId,
            UUID vaultId,
            UUID inviteId,
            UUID inviteeUserId,
            OffsetDateTime createdAt
    ) {
        ObjectNode meta = JsonNodeFactory.instance.objectNode();
        meta.put("inviteId", inviteId.toString());
        meta.put("inviteeUserId", inviteeUserId.toString());

        append(
                actorUserId,
                AuditScopeType.VAULT,
                vaultId,
                AuditEventTypeCodes.INVITE_REVOKED,
                meta,
                createdAt
        );
    }

    @Transactional
    public void appendInviteAccepted(
            UUID actorUserId,
            UUID vaultId,
            UUID inviteId,
            OffsetDateTime createdAt
    ) {
        ObjectNode meta = JsonNodeFactory.instance.objectNode();
        meta.put("inviteId", inviteId.toString());

        append(
                actorUserId,
                AuditScopeType.VAULT,
                vaultId,
                AuditEventTypeCodes.INVITE_ACCEPTED,
                meta,
                createdAt
        );
    }

    @Transactional
    public void appendInviteDeclined(
            UUID actorUserId,
            UUID vaultId,
            UUID inviteId,
            OffsetDateTime createdAt
    ) {
        ObjectNode meta = JsonNodeFactory.instance.objectNode();
        meta.put("inviteId", inviteId.toString());

        append(
                actorUserId,
                AuditScopeType.VAULT,
                vaultId,
                AuditEventTypeCodes.INVITE_DECLINED,
                meta,
                createdAt
        );
    }

    @Transactional
    public void appendMemberRoleChanged(
            UUID actorUserId,
            UUID vaultId,
            UUID targetUserId,
            VaultMemberRole newRole,
            OffsetDateTime createdAt
    ) {
        ObjectNode meta = JsonNodeFactory.instance.objectNode();
        meta.put("targetUserId", targetUserId.toString());
        meta.put("newRole", newRole.name());

        append(
                actorUserId,
                AuditScopeType.VAULT,
                vaultId,
                AuditEventTypeCodes.MEMBER_ROLE_CHANGED,
                meta,
                createdAt
        );
    }

    @Transactional
    public void appendVaultDeleted(
            UUID actorUserId,
            UUID vaultId,
            int affectedUserCount,
            int activeMemberCount,
            int pendingInviteCount,
            OffsetDateTime createdAt
    ) {
        ObjectNode meta = JsonNodeFactory.instance.objectNode();
        meta.put("vaultId", vaultId.toString());
        meta.put("affectedUserCount", affectedUserCount);
        meta.put("activeMemberCount", activeMemberCount);
        meta.put("pendingInviteCount", pendingInviteCount);

        append(
                actorUserId,
                AuditScopeType.VAULT,
                vaultId,
                AuditEventTypeCodes.VAULT_DELETED,
                meta,
                createdAt
        );
    }

    @Transactional
    public void appendOwnershipTransferred(
            UUID actorUserId,
            UUID vaultId,
            UUID targetUserId,
            OffsetDateTime createdAt
    ) {
        ObjectNode meta = JsonNodeFactory.instance.objectNode();
        meta.put("targetUserId", targetUserId.toString());
        meta.put("previousOwnerRole", VaultMemberRole.EDITOR.name());
        meta.put("newOwnerRole", VaultMemberRole.OWNER.name());

        append(
                actorUserId,
                AuditScopeType.VAULT,
                vaultId,
                AuditEventTypeCodes.OWNERSHIP_TRANSFERRED,
                meta,
                createdAt
        );
    }

    @Transactional
    public void appendMemberRevoked(
            UUID actorUserId,
            UUID vaultId,
            UUID targetUserId,
            OffsetDateTime createdAt
    ) {
        ObjectNode meta = JsonNodeFactory.instance.objectNode();
        meta.put("targetUserId", targetUserId.toString());

        append(
                actorUserId,
                AuditScopeType.VAULT,
                vaultId,
                AuditEventTypeCodes.MEMBER_REVOKED,
                meta,
                createdAt
        );
    }

    private void appendSimpleUserEvent(
            UUID userId,
            String eventType,
            OffsetDateTime createdAt
    ) {
        ObjectNode meta = JsonNodeFactory.instance.objectNode();
        meta.put("userId", userId.toString());

        append(
                userId,
                AuditScopeType.USER,
                userId,
                eventType,
                meta,
                createdAt
        );
    }

    private void appendObjectEvent(
            UUID actorUserId,
            UUID vaultId,
            String eventType,
            UUID objectId,
            int version,
            OffsetDateTime createdAt
    ) {
        ObjectNode meta = JsonNodeFactory.instance.objectNode();
        meta.put("objectId", objectId.toString());
        meta.put("version", version);

        append(
                actorUserId,
                AuditScopeType.VAULT,
                vaultId,
                eventType,
                meta,
                createdAt
        );
    }

    @Transactional
    public void appendVaultKeyRotated(
            UUID actorUserId,
            UUID vaultId,
            int previousVaultKeyVersion,
            int newVaultKeyVersion,
            int rotatedObjectCount,
            OffsetDateTime createdAt
    ) {
        ObjectNode meta = JsonNodeFactory.instance.objectNode();
        meta.put("previousVaultKeyVersion", previousVaultKeyVersion);
        meta.put("newVaultKeyVersion", newVaultKeyVersion);
        meta.put("rotatedObjectCount", rotatedObjectCount);

        append(
                actorUserId,
                AuditScopeType.VAULT,
                vaultId,
                AuditEventTypeCodes.VAULT_KEY_ROTATED,
                meta,
                createdAt
        );
    }

    private void append(
            UUID actorUserId,
            AuditScopeType scopeType,
            UUID scopeId,
            String eventType,
            JsonNode meta,
            OffsetDateTime createdAt
    ) {
        OffsetDateTime normalizedCreatedAt = normalizeAuditTimestamp(createdAt);
        OffsetDateTime updatedAt = normalizeAuditTimestamp(OffsetDateTime.now(ZoneOffset.UTC));

        auditScopeLockService.lock(scopeType, scopeId);

        byte[] prevEventHash = auditScopeHeadRepository
                .findById(new AuditScopeHeadId(scopeType, scopeId))
                .map(AuditScopeHead::getHeadEventHash)
                .or(() -> auditEventRepository.findTopByScopeTypeAndScopeIdOrderByEventIdDesc(scopeType, scopeId)
                .map(AuditEvent::getEventHash)
                )
                .orElse(null);

        JsonNode canonicalMeta = auditCanonicalJsonService.canonicalize(meta);

        byte[] eventHash = auditHashService.computeEventHash(
                actorUserId,
                scopeType,
                scopeId,
                eventType,
                canonicalMeta,
                normalizedCreatedAt,
                prevEventHash
        );

        byte[] eventSignature = auditSigningService.sign(eventHash);

        AuditEvent event = AuditEvent.builder()
                .actorUserId(actorUserId)
                .scopeType(scopeType)
                .scopeId(scopeId)
                .eventType(eventType)
                .meta(canonicalMeta)
                .eventHash(eventHash)
                .prevEventHash(prevEventHash)
                .signatureKeyId(auditSigningService.keyId())
                .eventSignature(eventSignature)
                .createdAt(normalizedCreatedAt)
                .build();

        AuditEvent savedEvent = auditEventRepository.save(event);

        auditScopeHeadRepository.save(AuditScopeHead.builder()
                .scopeType(scopeType)
                .scopeId(scopeId)
                .headEventId(savedEvent.getEventId())
                .headEventHash(savedEvent.getEventHash())
                .headCreatedAt(savedEvent.getCreatedAt())
                .updatedAt(updatedAt)
                .build());

        auditAnchorService.enqueueAnchor(savedEvent);
    }

    @Transactional
    public void appendRecordKeyRotated(
            UUID actorUserId,
            UUID vaultId,
            UUID objectId,
            int previousVersion,
            int newVersion,
            int vaultKeyVersion,
            OffsetDateTime createdAt
    ) {
        ObjectNode meta = JsonNodeFactory.instance.objectNode();
        meta.put("objectId", objectId.toString());
        meta.put("previousVersion", previousVersion);
        meta.put("newVersion", newVersion);
        meta.put("vaultKeyVersion", vaultKeyVersion);

        append(
                actorUserId,
                AuditScopeType.VAULT,
                vaultId,
                AuditEventTypeCodes.RECORD_KEY_ROTATED,
                meta,
                createdAt
        );
    }

    private OffsetDateTime normalizeAuditTimestamp(OffsetDateTime value) {
        return value.withOffsetSameInstant(ZoneOffset.UTC)
                .truncatedTo(ChronoUnit.MICROS);
    }
}
