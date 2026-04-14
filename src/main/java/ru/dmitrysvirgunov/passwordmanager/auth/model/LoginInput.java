package ru.dmitrysvirgunov.passwordmanager.auth.model;

public record LoginInput(
        String email,
        byte[] authSecret,
        String deviceName
) {
}