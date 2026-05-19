package ru.dmitrysvirgunov.passwordmanager.vault.dto.response.list;

import ru.dmitrysvirgunov.passwordmanager.vault.dto.response.object.VaultObjectRevisionResponse;

import java.util.List;
import java.util.UUID;

public record ListVaultObjectRevisionsResponse(
        UUID objectId,
        int currentVersion,
        boolean deleted,
        List<VaultObjectRevisionResponse> items
) {
}