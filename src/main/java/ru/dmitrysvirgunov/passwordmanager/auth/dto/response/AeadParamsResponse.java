package ru.dmitrysvirgunov.passwordmanager.auth.dto.response;

public record AeadParamsResponse(
        String algorithm,
        String ivBase64
) {
}