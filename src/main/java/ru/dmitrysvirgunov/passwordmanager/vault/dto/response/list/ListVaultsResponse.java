package ru.dmitrysvirgunov.passwordmanager.vault.dto.response.list;

import ru.dmitrysvirgunov.passwordmanager.vault.dto.response.vault.VaultSummaryResponse;

import java.util.List;

public record ListVaultsResponse(
        List<VaultSummaryResponse> items,
        int page,
        int size,
        long totalItems,
        int totalPages,
        long ownedCount,
        long sharedCount
) {
}
