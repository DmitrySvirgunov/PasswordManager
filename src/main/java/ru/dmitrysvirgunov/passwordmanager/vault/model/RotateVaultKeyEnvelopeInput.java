package ru.dmitrysvirgunov.passwordmanager.vault.model;

import tools.jackson.databind.JsonNode;

import java.util.UUID;

public record RotateVaultKeyEnvelopeInput(
        UUID recipientUserId,
        int recipientEncryptionKeyVersion,
        byte[] encryptedVaultKey,
        JsonNode envelopeParams
) {
}