package ru.dmitrysvirgunov.passwordmanager.auth.dto.response;

public record CurrentUserResponse(
        String userId,
        String email,
        String sessionId,
        String issuer
) {
}