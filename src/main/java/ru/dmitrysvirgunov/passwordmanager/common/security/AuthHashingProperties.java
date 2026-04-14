package ru.dmitrysvirgunov.passwordmanager.common.security;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "security.auth-hash")
public record AuthHashingProperties(
        String algorithm,
        int iterations,
        int memoryKb,
        int parallelism,
        int hashLengthBytes,
        int saltLengthBytes
) {
}
