package ru.dmitrysvirgunov.passwordmanager.vault.entity;

import jakarta.persistence.Column;
import jakarta.persistence.EmbeddedId;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import lombok.*;

import java.time.OffsetDateTime;

@Entity
@Table(name = "vault_blob_parts")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class VaultBlobPart {

    @EmbeddedId
    private VaultBlobPartId id;

    @Column(name = "ciphertext", nullable = false)
    private byte[] ciphertext;

    @Column(name = "ciphertext_sha256", nullable = false)
    private byte[] ciphertextSha256;

    @Column(name = "ciphertext_size_bytes", nullable = false)
    private int ciphertextSizeBytes;

    @Column(name = "created_at", nullable = false)
    private OffsetDateTime createdAt;
}
