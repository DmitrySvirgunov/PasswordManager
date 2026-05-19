package ru.dmitrysvirgunov.passwordmanager.vault.entity;

import jakarta.persistence.*;
import lombok.*;
import ru.dmitrysvirgunov.passwordmanager.vault.model.VaultBlobStatus;

import java.time.OffsetDateTime;
import java.util.UUID;

@Entity
@Table(name = "vault_blobs")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class VaultBlob {

    @Id
    @Column(name = "blob_id", nullable = false)
    private UUID blobId;

    @Column(name = "vault_id", nullable = false)
    private UUID vaultId;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false)
    private VaultBlobStatus status;

    @Column(name = "ciphertext_size_bytes", nullable = false)
    private long ciphertextSizeBytes;

    @Column(name = "chunk_size_bytes", nullable = false)
    private int chunkSizeBytes;

    @Column(name = "chunk_count", nullable = false)
    private int chunkCount;

    @Column(name = "ciphertext_sha256")
    private byte[] ciphertextSha256;

    @Column(name = "created_by_user_id", nullable = false)
    private UUID createdByUserId;

    @Column(name = "created_at", nullable = false)
    private OffsetDateTime createdAt;

    @Column(name = "completed_at")
    private OffsetDateTime completedAt;
}
