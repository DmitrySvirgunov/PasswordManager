package ru.dmitrysvirgunov.passwordmanager.auth.dto.request;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

public record KdfParamsRequest(

        @NotBlank
        String algorithm,

        @NotBlank
        String saltBase64,

        @NotNull
        @Min(1)
        Integer iterations,

        @NotNull
        @Min(1)
        Integer memoryKb,

        @NotNull
        @Min(1)
        @Max(32)
        Integer parallelism

) {}
