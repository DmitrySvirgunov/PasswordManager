package ru.dmitrysvirgunov.passwordmanager.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "app.mail")
public record MailModeProperties(
        MailMode mode,
        String from,
        String verifyBaseUrl
) {
}