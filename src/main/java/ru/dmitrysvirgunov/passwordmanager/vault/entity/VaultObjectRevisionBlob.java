package ru.dmitrysvirgunov.passwordmanager.vault.entity;

import jakarta.persistence.Column;
import jakarta.persistence.EmbeddedId;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import lombok.*;

import java.time.OffsetDateTime;
import java.util.UUID;

@Entity
@Table(name = "vault_object_revision_blobs")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class VaultObjectRevisionBlob {

    @EmbeddedId
    private VaultObjectRevisionBlobId id;

    @Column(name = "blob_id", nullable = false)
    private UUID blobId;

    @Column(name = "created_at", nullable = false)
    private OffsetDateTime createdAt;
}
