package ru.dmitrysvirgunov.passwordmanager.auth.model;

public record KdfParams(
        String algorithm,
        byte[] salt,
        int iterations,
        int memoryKb,
        int parallelism
) {
}