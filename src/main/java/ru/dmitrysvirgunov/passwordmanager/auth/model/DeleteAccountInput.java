package ru.dmitrysvirgunov.passwordmanager.auth.model;

public record DeleteAccountInput(
        byte[] currentAuthSecret
) {
}
