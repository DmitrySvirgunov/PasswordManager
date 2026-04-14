package ru.dmitrysvirgunov.passwordmanager.auth.dto.response;

public record VerifyEmailResponse(
        String email,
        VerifyEmailStatus status
) {
}