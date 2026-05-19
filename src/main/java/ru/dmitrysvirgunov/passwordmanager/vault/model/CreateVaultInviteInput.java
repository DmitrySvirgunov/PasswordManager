package ru.dmitrysvirgunov.passwordmanager.vault.model;

import tools.jackson.databind.JsonNode;

public record CreateVaultInviteInput(
        String inviteeEmail,
        VaultMemberRole role,
        byte[] encryptedVaultKey,
        JsonNode envelopeParams
) {
}