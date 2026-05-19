package ru.dmitrysvirgunov.passwordmanager.auth.dto.response;

public record PreloginResponse(
        KdfParamsResponse clientKdfParams
) {
}