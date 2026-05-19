package ru.dmitrysvirgunov.passwordmanager.vault.dto.response.list;

import ru.dmitrysvirgunov.passwordmanager.vault.dto.response.vault.VaultEnvelopeResponse;

import java.util.List;
import java.util.UUID;

public record ListVaultEnvelopesResponse(
        UUID vaultId,
        int currentVaultKeyVersion,
        List<VaultEnvelopeResponse> items
) {
}