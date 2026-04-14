package ru.dmitrysvirgunov.passwordmanager.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "app.registration")
public record RegistrationProperties(
        RegistrationMode mode
) {
}