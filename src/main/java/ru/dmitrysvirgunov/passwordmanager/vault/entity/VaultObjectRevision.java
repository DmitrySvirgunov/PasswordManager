package ru.dmitrysvirgunov.passwordmanager.vault.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;
import ru.dmitrysvirgunov.passwordmanager.common.model.AeadParams;
import tools.jackson.databind.JsonNode;

import java.time.OffsetDateTime;
import java.util.UUID;

@Entity
@Table(name = "vault_object_revisions")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class VaultObjectRevision {

    @Id
    @Column(name = "revision_id", nullable = false)
    private UUID revisionId;

    @Column(name = "object_id", nullable = false)
    private UUID objectId;

    @Column(name = "version", nullable = false)
    private int version;

    @Column(name = "ciphertext", nullable = false)
    private byte[] ciphertext;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "content_aead_params", nullable = false, columnDefinition = "jsonb")
    private AeadParams contentAeadParams;

    @Column(name = "wrapped_record_key", nullable = false)
    private byte[] wrappedRecordKey;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "record_key_wrap_params", nullable = false, columnDefinition = "jsonb")
    private JsonNode recordKeyWrapParams;

    @Column(name = "record_key_wrapped_by_vault_key_version", nullable = false)
    private int recordKeyWrappedByVaultKeyVersion;

    @Column(name = "encrypted_package_hash", nullable = false)
    private byte[] encryptedPackageHash;

    @Column(name = "client_signature", nullable = false)
    private byte[] clientSignature;

    @Column(name = "signature_format_version", nullable = false)
    private int signatureFormatVersion;

    @Column(name = "signature_key_version", nullable = false)
    private int signatureKeyVersion;

    @Column(name = "signed_by_user_id")
    private UUID signedByUserId;

    @Column(name = "created_at", nullable = false)
    private OffsetDateTime createdAt;
}
