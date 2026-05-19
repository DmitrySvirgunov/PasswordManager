package ru.dmitrysvirgunov.passwordmanager.vault.dto.response.blob;

import ru.dmitrysvirgunov.passwordmanager.vault.model.VaultBlobReferenceRole;

import java.util.UUID;

public record VaultBlobReferenceResponse(
        UUID blobId,
        VaultBlobReferenceRole role
) {
}
