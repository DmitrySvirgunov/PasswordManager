package ru.dmitrysvirgunov.passwordmanager.vault.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import ru.dmitrysvirgunov.passwordmanager.vault.model.VaultMemberRole;
import tools.jackson.databind.JsonNode;

public record CreateVaultInviteRequest(

        @NotBlank
        @Email
        String inviteeEmail,

        @NotNull
        VaultMemberRole role,

        @NotBlank
        String encryptedVaultKeyBase64,

        @NotNull
        JsonNode envelopeParams

) {
}