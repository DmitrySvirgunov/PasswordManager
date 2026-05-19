package ru.dmitrysvirgunov.passwordmanager.vault.dto.response.command;

import ru.dmitrysvirgunov.passwordmanager.vault.model.VaultInviteStatus;

import java.time.OffsetDateTime;
import java.util.UUID;

public record CreateVaultInviteResponse(
        UUID inviteId,
        UUID inviteeUserId,
        String inviteeEmail,
        VaultInviteStatus status,
        OffsetDateTime expiresAt,
        OffsetDateTime createdAt
) {
}