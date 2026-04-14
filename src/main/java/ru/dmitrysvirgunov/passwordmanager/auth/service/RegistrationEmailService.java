package ru.dmitrysvirgunov.passwordmanager.auth.service;

public interface RegistrationEmailService {
    void sendVerificationEmail(String email, String rawToken);
}