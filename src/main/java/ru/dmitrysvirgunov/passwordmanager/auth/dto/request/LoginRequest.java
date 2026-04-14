package ru.dmitrysvirgunov.passwordmanager.auth.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record LoginRequest(

        @NotBlank
        @Email
        @Size(max = 320)
        String email,

        @NotBlank
        String authSecretBase64,

        @Size(max = 255)
        String deviceName

) {}