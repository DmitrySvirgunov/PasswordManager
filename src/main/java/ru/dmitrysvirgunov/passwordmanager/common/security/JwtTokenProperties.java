package ru.dmitrysvirgunov.passwordmanager.common.security;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "app.security.jwt")
public record JwtTokenProperties(
        String issuer,
        String secretBase64,
        long accessTtlMinutes
) {
}