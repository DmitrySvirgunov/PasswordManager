package ru.dmitrysvirgunov.passwordmanager.common.model;

public record AeadParams(
        String algorithm,
        byte[] iv
) {
}