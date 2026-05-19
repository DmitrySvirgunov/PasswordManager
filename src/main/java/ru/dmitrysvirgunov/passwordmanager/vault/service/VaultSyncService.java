package ru.dmitrysvirgunov.passwordmanager.vault.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ru.dmitrysvirgunov.passwordmanager.vault.dto.response.sync.GetUserSyncResponse;
import ru.dmitrysvirgunov.passwordmanager.vault.dto.response.sync.GetVaultSyncResponse;
import ru.dmitrysvirgunov.passwordmanager.vault.dto.response.sync.SyncEventResponse;
import ru.dmitrysvirgunov.passwordmanager.vault.dto.response.sync.UserSyncEventResponse;
import ru.dmitrysvirgunov.passwordmanager.vault.entity.SyncLog;
import ru.dmitrysvirgunov.passwordmanager.vault.model.SyncOpType;
import ru.dmitrysvirgunov.passwordmanager.vault.repository.SyncLogRepository;

import java.time.OffsetDateTime;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class VaultSyncService {

    private final SyncLogRepository syncLogRepository;
    private final VaultAccessService vaultAccessService;

    @Transactional
    public void appendUpsert(
            UUID vaultId,
            UUID objectId,
            int version,
            UUID actorUserId,
            OffsetDateTime createdAt
    ) {
        SyncLog syncLog = SyncLog.builder()
                .vaultId(vaultId)
                .objectId(objectId)
                .version(version)
                .actorUserId(actorUserId)
                .opType(SyncOpType.UPSERT)
                .createdAt(createdAt)
                .build();

        syncLogRepository.save(syncLog);
    }

    @Transactional
    public void appendDelete(
            UUID vaultId,
            UUID objectId,
            int version,
            UUID actorUserId,
            OffsetDateTime createdAt
    ) {
        SyncLog syncLog = SyncLog.builder()
                .vaultId(vaultId)
                .objectId(objectId)
                .version(version)
                .actorUserId(actorUserId)
                .opType(SyncOpType.DELETE)
                .createdAt(createdAt)
                .build();

        syncLogRepository.save(syncLog);
    }

    @Transactional(readOnly = true)
    public GetVaultSyncResponse getVaultSync(UUID vaultId, long afterSeq, Jwt jwt) {
        UUID currentUserId = UUID.fromString(jwt.getSubject());
        OffsetDateTime now = OffsetDateTime.now();

        vaultAccessService.requireReadableMembership(vaultId, currentUserId, now);

        var logs = syncLogRepository.findByVaultIdAndSeqGreaterThanOrderBySeqAsc(vaultId, afterSeq);

        var events = logs.stream()
                .map(log -> new SyncEventResponse(
                        log.getSeq(),
                        log.getObjectId(),
                        log.getVersion(),
                        log.getOpType(),
                        log.getCreatedAt()
                ))
                .toList();

        long lastSeq = logs.isEmpty() ? afterSeq : logs.get(logs.size() - 1).getSeq();

        return new GetVaultSyncResponse(afterSeq, lastSeq, events);
    }

    @Transactional(readOnly = true)
    public GetUserSyncResponse getUserSync(long afterSeq, Jwt jwt) {
        UUID currentUserId = UUID.fromString(jwt.getSubject());

        var logs = syncLogRepository.findByTargetUserIdAndSeqGreaterThanOrderBySeqAsc(
                currentUserId,
                afterSeq
        );

        var events = logs.stream()
                .map(log -> new UserSyncEventResponse(
                        log.getSeq(),
                        resolveUserSyncVaultId(log),
                        log.getObjectId(),
                        log.getInviteId(),
                        log.getVersion(),
                        log.getOpType(),
                        log.getCreatedAt()
                ))
                .toList();

        long lastSeq = logs.isEmpty() ? afterSeq : logs.get(logs.size() - 1).getSeq();

        return new GetUserSyncResponse(afterSeq, lastSeq, events);
    }

    @Transactional
    public void appendMembershipChanged(
            UUID vaultId,
            UUID actorUserId,
            OffsetDateTime createdAt
    ) {
        saveMembershipChanged(vaultId, null, null, actorUserId, createdAt);
    }

    @Transactional
    public void appendTargetedMembershipChanged(
            UUID vaultId,
            UUID targetUserId,
            UUID inviteId,
            UUID actorUserId,
            OffsetDateTime createdAt
    ) {
        saveMembershipChanged(vaultId, targetUserId, inviteId, actorUserId, createdAt);
    }

    private void saveMembershipChanged(
            UUID vaultId,
            UUID targetUserId,
            UUID inviteId,
            UUID actorUserId,
            OffsetDateTime createdAt
    ) {
        SyncLog syncLog = SyncLog.builder()
                .vaultId(vaultId)
                .objectId(null)
                .targetUserId(targetUserId)
                .inviteId(inviteId)
                .version(null)
                .actorUserId(actorUserId)
                .opType(SyncOpType.MEMBERSHIP_CHANGED)
                .createdAt(createdAt)
                .build();

        syncLogRepository.save(syncLog);
    }

    @Transactional
    public void appendRotateVaultKey(
            UUID vaultId,
            UUID actorUserId,
            OffsetDateTime createdAt
    ) {
        SyncLog syncLog = SyncLog.builder()
                .vaultId(vaultId)
                .objectId(null)
                .version(null)
                .actorUserId(actorUserId)
                .opType(SyncOpType.ROTATE_VAULT_KEY)
                .createdAt(createdAt)
                .build();

        syncLogRepository.save(syncLog);
    }

    @Transactional
    public void appendTargetedVaultDeleted(
            UUID vaultId,
            UUID targetUserId,
            UUID actorUserId,
            OffsetDateTime createdAt
    ) {
        SyncLog syncLog = SyncLog.builder()
                .vaultId(null)
                .vaultRefId(vaultId)
                .objectId(null)
                .targetUserId(targetUserId)
                .inviteId(null)
                .version(null)
                .actorUserId(actorUserId)
                .opType(SyncOpType.VAULT_DELETED)
                .createdAt(createdAt)
                .build();

        syncLogRepository.save(syncLog);
    }

    private UUID resolveUserSyncVaultId(SyncLog log) {
        return log.getVaultRefId() != null ? log.getVaultRefId() : log.getVaultId();
    }
}
