package ru.dmitrysvirgunov.passwordmanager.vault.entity;

import tools.jackson.databind.JsonNode;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.OffsetDateTime;
import java.util.UUID;

@Entity
@Table(name = "vault_key_envelopes")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class VaultKeyEnvelope {

    @Id
    @Column(name = "envelope_id", nullable = false)
    private UUID envelopeId;

    @Column(name = "vault_id", nullable = false)
    private UUID vaultId;

    @Column(name = "vault_key_version", nullable = false)
    private int vaultKeyVersion;

    @Column(name = "recipient_user_id", nullable = false)
    private UUID recipientUserId;

    @Column(name = "recipient_encryption_key_version", nullable = false)
    private int recipientEncryptionKeyVersion;

    @Column(name = "envelope_version", nullable = false)
    private int envelopeVersion;

    @Column(name = "encrypted_vault_key", nullable = false)
    private byte[] encryptedVaultKey;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "envelope_params", nullable = false, columnDefinition = "jsonb")
    private JsonNode envelopeParams;

    @Column(name = "created_by_user_id", nullable = false)
    private UUID createdByUserId;

    @Column(name = "created_at", nullable = false)
    private OffsetDateTime createdAt;

    @Column(name = "revoked_at")
    private OffsetDateTime revokedAt;
}