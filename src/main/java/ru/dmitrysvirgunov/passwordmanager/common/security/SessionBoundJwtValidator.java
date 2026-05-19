package ru.dmitrysvirgunov.passwordmanager.common.security;

import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import ru.dmitrysvirgunov.passwordmanager.auth.entity.UserAuth;
import ru.dmitrysvirgunov.passwordmanager.auth.entity.UserSession;
import ru.dmitrysvirgunov.passwordmanager.auth.repository.UserAuthRepository;
import ru.dmitrysvirgunov.passwordmanager.auth.repository.UserSessionRepository;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.Optional;
import java.util.UUID;

@Component
@RequiredArgsConstructor
public class SessionBoundJwtValidator implements OAuth2TokenValidator<Jwt> {

    private final UserAuthRepository userAuthRepository;
    private final UserSessionRepository userSessionRepository;

    @Override
    public OAuth2TokenValidatorResult validate(Jwt token) {
        UUID userId = parseUuid(token.getSubject());
        UUID sessionId = parseUuid(token.getClaimAsString("sid"));
        Instant issuedAt = token.getIssuedAt();

        if (userId == null || sessionId == null || issuedAt == null) {
            return failure("JWT is missing required subject/session claims");
        }

        Optional<UserSession> userSession = userSessionRepository.findById(sessionId);
        if (userSession.isEmpty()
                || !userId.equals(userSession.get().getUserId())
                || userSession.get().getRevokedAt() != null) {
            return failure("JWT session is no longer active");
        }

        Optional<UserAuth> userAuth = userAuthRepository.findById(userId);
        if (userAuth.isEmpty()) {
            return failure("JWT user auth state is missing");
        }

        OffsetDateTime passwordChangedAt = userAuth.get().getPasswordChangedAt();
        if (passwordChangedAt != null && issuedAt.isBefore(passwordChangedAt.toInstant())) {
            return failure("JWT was issued before the current password change");
        }

        return OAuth2TokenValidatorResult.success();
    }

    private UUID parseUuid(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }

        try {
            return UUID.fromString(value);
        } catch (IllegalArgumentException ignored) {
            return null;
        }
    }

    private OAuth2TokenValidatorResult failure(String description) {
        return OAuth2TokenValidatorResult.failure(
                new OAuth2Error("invalid_token", description, null)
        );
    }
}
