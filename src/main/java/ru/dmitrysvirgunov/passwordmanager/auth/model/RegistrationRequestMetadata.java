package ru.dmitrysvirgunov.passwordmanager.auth.model;

public record RegistrationRequestMetadata(
        String clientIp,
        String userAgent
) {
}
