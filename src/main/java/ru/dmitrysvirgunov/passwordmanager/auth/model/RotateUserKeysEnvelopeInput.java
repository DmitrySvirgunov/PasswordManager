package ru.dmitrysvirgunov.passwordmanager.auth.model;

import tools.jackson.databind.JsonNode;

import java.util.UUID;

public record RotateUserKeysEnvelopeInput(
        UUID vaultId,
        byte[] encryptedVaultKey,
        JsonNode envelopeParams
) {
}
