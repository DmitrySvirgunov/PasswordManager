package ru.dmitrysvirgunov.passwordmanager.auth.dto.response;

import java.time.Instant;
import java.util.UUID;

public record AuthTokensResponse(
        UUID sessionId,
        String accessToken,
        Instant accessTokenExpiresAt,
        String refreshToken,
        Instant refreshTokenExpiresAt
) {
}