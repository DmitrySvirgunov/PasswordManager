package ru.dmitrysvirgunov.passwordmanager.vault.dto.response.membership;

import ru.dmitrysvirgunov.passwordmanager.vault.model.VaultMemberRole;
import ru.dmitrysvirgunov.passwordmanager.vault.model.VaultInviteStatus;

import java.time.OffsetDateTime;
import java.util.UUID;

public record VaultInviteResponse(
        UUID inviteId,
        String inviteeEmail,
        UUID inviteeUserId,
        VaultMemberRole role,
        VaultInviteStatus status,
        OffsetDateTime expiresAt,
        OffsetDateTime createdAt,
        OffsetDateTime acceptedAt,
        OffsetDateTime revokedAt
) {
}