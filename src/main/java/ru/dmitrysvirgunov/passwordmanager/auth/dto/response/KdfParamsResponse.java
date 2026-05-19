package ru.dmitrysvirgunov.passwordmanager.auth.dto.response;

public record KdfParamsResponse(
        String algorithm,
        int iterations,
        int memoryKb,
        int parallelism,
        String saltBase64
) {
}