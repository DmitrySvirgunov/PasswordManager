package ru.dmitrysvirgunov.passwordmanager.common.exception;

public class TokenExpiredException extends ApplicationException {

    public TokenExpiredException(String message) {
        super(message);
    }
}