package ru.dmitrysvirgunov.passwordmanager.vault.dto.response.list;

import ru.dmitrysvirgunov.passwordmanager.vault.dto.response.object.VaultObjectSnapshotResponse;

import java.util.List;

public record ListVaultObjectsResponse(
        List<VaultObjectSnapshotResponse> items,
        int page,
        int size,
        long totalItems,
        int totalPages
) {
}
