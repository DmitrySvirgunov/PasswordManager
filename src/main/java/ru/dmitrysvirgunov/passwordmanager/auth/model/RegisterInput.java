package ru.dmitrysvirgunov.passwordmanager.auth.model;

public record RegisterInput(
        String email,
        byte[] authSecret,
        KdfParams clientKdfParams,
        byte[] publicKey,
        byte[] encryptedPrivateKey,
        KeyParams keyParams
) {
}
