package ru.dmitrysvirgunov.passwordmanager.auth.model;

import java.util.List;

public record RotateUserKeysInput(
        byte[] currentAuthSecret,
        byte[] publicEncryptionKey,
        byte[] encryptedPrivateEncryptionKey,
        AsymmetricKeyParams encryptionKeyParams,
        byte[] publicSigningKey,
        byte[] encryptedPrivateSigningKey,
        AsymmetricKeyParams signingKeyParams,
        List<RotateUserKeysEnvelopeInput> envelopes
) {
}
