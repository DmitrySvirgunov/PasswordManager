package ru.dmitrysvirgunov.passwordmanager.auth.model;

import ru.dmitrysvirgunov.passwordmanager.common.model.AeadParams;

public record AsymmetricKeyParams(
        String keyAlgorithm,
        String publicKeyEncoding,
        String privateKeyEncoding,
        AeadParams privateKeyWrap
) {
}