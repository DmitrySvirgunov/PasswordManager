package ru.dmitrysvirgunov.passwordmanager.vault.model;

import tools.jackson.databind.JsonNode;
import ru.dmitrysvirgunov.passwordmanager.common.model.AeadParams;

public record CreateVaultInput(
        byte[] nameCiphertext,
        AeadParams nameAeadParams,
        byte[] encryptedVaultKey,
        JsonNode envelopeParams
) {
}