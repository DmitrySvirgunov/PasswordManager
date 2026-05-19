package ru.dmitrysvirgunov.passwordmanager.vault.dto.response.command;

import java.time.OffsetDateTime;
import java.util.UUID;

public record DeleteVaultObjectResponse(
        UUID objectId,
        UUID revisionId,
        int version,
        OffsetDateTime deletedAt
) {
}