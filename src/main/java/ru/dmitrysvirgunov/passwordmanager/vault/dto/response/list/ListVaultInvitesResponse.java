package ru.dmitrysvirgunov.passwordmanager.vault.dto.response.list;

import ru.dmitrysvirgunov.passwordmanager.vault.dto.response.membership.VaultInviteResponse;

import java.util.List;
import java.util.UUID;

public record ListVaultInvitesResponse(
        UUID vaultId,
        List<VaultInviteResponse> items
) {
}