package ru.dmitrysvirgunov.passwordmanager.vault.dto.request;

import jakarta.validation.constraints.NotNull;
import ru.dmitrysvirgunov.passwordmanager.vault.model.VaultMemberRole;

public record ChangeVaultMemberRoleRequest(
        @NotNull
        VaultMemberRole role
) {
}