package ru.dmitrysvirgunov.passwordmanager.vault.dto.response.membership;

import ru.dmitrysvirgunov.passwordmanager.vault.model.VaultMemberRole;
import ru.dmitrysvirgunov.passwordmanager.vault.model.VaultMemberStatus;

import java.time.OffsetDateTime;
import java.util.UUID;

public record VaultMemberResponse(
        UUID userId,
        String email,
        VaultMemberRole role,
        VaultMemberStatus status,
        OffsetDateTime joinedAt,
        OffsetDateTime expiresAt,
        OffsetDateTime revokedAt
) {
}