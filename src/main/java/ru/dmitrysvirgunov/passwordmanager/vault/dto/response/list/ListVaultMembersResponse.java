package ru.dmitrysvirgunov.passwordmanager.vault.dto.response.list;

import ru.dmitrysvirgunov.passwordmanager.vault.dto.response.membership.VaultMemberResponse;

import java.util.List;
import java.util.UUID;

public record ListVaultMembersResponse(
        UUID vaultId,
        List<VaultMemberResponse> items
) {
}