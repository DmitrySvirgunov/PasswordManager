package ru.dmitrysvirgunov.passwordmanager.vault.model;

import java.util.UUID;

public record BlobReferenceInput(
        UUID blobId,
        VaultBlobReferenceRole role
) {
}
