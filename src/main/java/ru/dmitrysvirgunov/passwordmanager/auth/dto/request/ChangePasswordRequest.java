package ru.dmitrysvirgunov.passwordmanager.auth.dto.request;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

public record ChangePasswordRequest(

        @NotBlank
        String currentAuthSecretBase64,

        @NotBlank
        String newAuthSecretBase64,

        @NotNull
        @Valid
        KdfParamsRequest newClientKdfParams,

        @NotBlank
        String newWrappedAccountRootKeyBase64,

        @NotNull
        @Valid
        AeadParamsRequest newAccountRootWrapParams
) {
}
