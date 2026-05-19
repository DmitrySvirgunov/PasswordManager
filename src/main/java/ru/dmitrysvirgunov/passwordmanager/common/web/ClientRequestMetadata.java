package ru.dmitrysvirgunov.passwordmanager.common.web;

public record ClientRequestMetadata(
        String clientIp,
        String userAgent
) {
}
