package ru.dmitrysvirgunov.passwordmanager.vault.dto.response.sync;

import java.util.List;

public record GetVaultSyncResponse(
        long afterSeq,
        long lastSeq,
        List<SyncEventResponse> events
) {
}