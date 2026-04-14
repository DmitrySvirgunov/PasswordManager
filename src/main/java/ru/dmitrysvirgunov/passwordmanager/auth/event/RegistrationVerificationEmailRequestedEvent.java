package ru.dmitrysvirgunov.passwordmanager.auth.event;

public record RegistrationVerificationEmailRequestedEvent(
        String email,
        String rawToken
) {
}
