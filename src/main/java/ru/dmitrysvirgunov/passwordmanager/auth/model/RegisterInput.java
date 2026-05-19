package ru.dmitrysvirgunov.passwordmanager.auth.model;

import ru.dmitrysvirgunov.passwordmanager.common.model.AeadParams;

public record RegisterInput(
        String email,
        byte[] authSecret,
        KdfParams clientKdfParams,

        byte[] wrappedAccountRootKey,
        AeadParams accountRootWrapParams,

        byte[] publicEncryptionKey,
        byte[] encryptedPrivateEncryptionKey,
        AsymmetricKeyParams encryptionKeyParams,

        byte[] publicSigningKey,
        byte[] encryptedPrivateSigningKey,
        AsymmetricKeyParams signingKeyParams
) {
}