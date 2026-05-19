package ru.dmitrysvirgunov.passwordmanager.vault.dto.response.list;

import ru.dmitrysvirgunov.passwordmanager.vault.dto.response.membership.IncomingVaultInviteResponse;

import java.util.List;

public record ListIncomingVaultInvitesResponse(
        List<IncomingVaultInviteResponse> items
) {
}