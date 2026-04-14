package ru.dmitrysvirgunov.passwordmanager.auth.model;

public record AuthHashParams(
        String algorithm,
        int iterations,
        int memoryKb,
        int parallelism,
        int hashLengthBytes
) {
}
