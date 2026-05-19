package ru.dmitrysvirgunov.passwordmanager.vault.dto.response.membership;

import ru.dmitrysvirgunov.passwordmanager.vault.model.VaultInviteStatus;
import ru.dmitrysvirgunov.passwordmanager.vault.model.VaultMemberRole;

import java.time.OffsetDateTime;
import java.util.UUID;

public record IncomingVaultInviteResponse(
        UUID inviteId,
        UUID vaultId,
        UUID createdByUserId,
        String createdByEmail,
        String inviteeEmail,
        VaultMemberRole role,
        VaultInviteStatus status,
        OffsetDateTime createdAt,
        OffsetDateTime expiresAt,
        OffsetDateTime acceptedAt,
        OffsetDateTime revokedAt
) {
}