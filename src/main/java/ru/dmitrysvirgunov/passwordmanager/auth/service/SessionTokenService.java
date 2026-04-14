package ru.dmitrysvirgunov.passwordmanager.auth.service;

import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

@Service
public class SessionTokenService {

    private static final int REFRESH_TOKEN_BYTES = 32;

    private final SecureRandom secureRandom = new SecureRandom();

    public IssuedRefreshToken issueRefreshToken() {
        byte[] rawBytes = new byte[REFRESH_TOKEN_BYTES];
        secureRandom.nextBytes(rawBytes);

        String rawToken = Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(rawBytes);

        byte[] tokenHash = sha256(rawToken);

        return new IssuedRefreshToken(rawToken, tokenHash);
    }

    public byte[] hashPresentedRefreshToken(String rawToken) {
        if (rawToken == null || rawToken.isBlank()) {
            throw new IllegalArgumentException("rawToken must not be blank");
        }
        return sha256(rawToken);
    }

    private byte[] sha256(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(value.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 algorithm is not available", e);
        }
    }

    public record IssuedRefreshToken(
            String rawToken,
            byte[] tokenHash
    ) {
    }
}