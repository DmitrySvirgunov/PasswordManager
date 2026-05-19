package ru.dmitrysvirgunov.passwordmanager.vault.dto.response.list;

import ru.dmitrysvirgunov.passwordmanager.vault.dto.response.vault.VaultSharingMaterialResponse;

import java.util.List;
import java.util.UUID;

public record ListVaultSharingMaterialsResponse(
        UUID vaultId,
        List<VaultSharingMaterialResponse> items
) {
}