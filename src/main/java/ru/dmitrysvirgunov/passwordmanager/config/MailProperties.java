package ru.dmitrysvirgunov.passwordmanager.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "app.mail")
public record MailProperties(
        String from,
        String verifyBaseUrl
) {
}