package ru.dmitrysvirgunov.passwordmanager.auth.service;

public class NoopRegistrationEmailService implements RegistrationEmailService {

    @Override
    public void sendVerificationEmail(String email, String rawToken) {
        // intentionally no-op
    }
}