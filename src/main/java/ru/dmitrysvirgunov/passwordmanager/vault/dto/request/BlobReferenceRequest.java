package ru.dmitrysvirgunov.passwordmanager.vault.dto.request;

import jakarta.validation.constraints.NotNull;
import ru.dmitrysvirgunov.passwordmanager.vault.model.VaultBlobReferenceRole;

import java.util.UUID;

public record BlobReferenceRequest(

        @NotNull
        UUID blobId,

        @NotNull
        VaultBlobReferenceRole role

) {
}
