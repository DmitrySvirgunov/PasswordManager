package ru.dmitrysvirgunov.passwordmanager.vault.dto.response.sync;

import java.util.List;

public record GetUserSyncResponse(
        long afterSeq,
        long lastSeq,
        List<UserSyncEventResponse> events
) {
}
