package ru.dmitrysvirgunov.passwordmanager.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "app.anti-abuse")
public record AntiAbuseProperties(
        boolean enabled,
        int emailLimit,
        long emailWindowMinutes,
        int ipLimit,
        long ipWindowMinutes
) {
}