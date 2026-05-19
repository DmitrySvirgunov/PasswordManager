package ru.dmitrysvirgunov.passwordmanager.vault.model;

import ru.dmitrysvirgunov.passwordmanager.common.model.AeadParams;

import java.util.List;

public record RotateVaultKeyInput(
        int expectedCurrentVaultKeyVersion,
        int newVaultKeyVersion,
        byte[] nameCiphertext,
        AeadParams nameAeadParams,
        List<RotateVaultKeyEnvelopeInput> envelopes,
        List<RotateVaultObjectInput> objects
) {
}