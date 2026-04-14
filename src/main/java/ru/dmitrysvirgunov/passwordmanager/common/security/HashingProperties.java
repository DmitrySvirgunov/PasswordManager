package ru.dmitrysvirgunov.passwordmanager.common.security;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "security.hashing")
public record HashingProperties(
        String hmacSecretBase64
) {
}