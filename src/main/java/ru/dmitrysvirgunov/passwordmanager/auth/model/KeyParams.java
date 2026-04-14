package ru.dmitrysvirgunov.passwordmanager.auth.model;

public record KeyParams(
        String keyAlgorithm,
        String privateKeyWrapAlgorithm,
        byte[] privateKeyWrapIv,
        byte[] privateKeyWrapSalt
) {
}