package ru.dmitrysvirgunov.passwordmanager.vault.dto.response.sync;

import ru.dmitrysvirgunov.passwordmanager.vault.model.SyncOpType;

import java.time.OffsetDateTime;
import java.util.UUID;

public record SyncEventResponse(
        long seq,
        UUID objectId,
        Integer version,
        SyncOpType opType,
        OffsetDateTime createdAt
) {
}