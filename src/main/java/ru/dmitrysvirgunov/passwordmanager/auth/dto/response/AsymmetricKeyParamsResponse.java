package ru.dmitrysvirgunov.passwordmanager.auth.dto.response;

public record AsymmetricKeyParamsResponse(
        String keyAlgorithm,
        String publicKeyEncoding,
        String privateKeyEncoding,
        AeadParamsResponse privateKeyWrap
) {
}