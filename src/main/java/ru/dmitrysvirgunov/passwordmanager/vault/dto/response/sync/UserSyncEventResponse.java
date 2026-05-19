package ru.dmitrysvirgunov.passwordmanager.vault.dto.response.sync;

import ru.dmitrysvirgunov.passwordmanager.vault.model.SyncOpType;

import java.time.OffsetDateTime;
import java.util.UUID;

public record UserSyncEventResponse(
        long seq,
        UUID vaultId,
        UUID objectId,
        UUID inviteId,
        Integer version,
        SyncOpType opType,
        OffsetDateTime createdAt
) {
}
