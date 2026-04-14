package ru.dmitrysvirgunov.passwordmanager.auth.dto.response;

public record RegisterResponse(
        String email,
        RegistrationStatus status
) {
}