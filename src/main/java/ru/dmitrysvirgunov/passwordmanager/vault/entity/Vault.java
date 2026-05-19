package ru.dmitrysvirgunov.passwordmanager.vault.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;
import ru.dmitrysvirgunov.passwordmanager.common.model.AeadParams;

import java.time.OffsetDateTime;
import java.util.UUID;

@Entity
@Table(name = "vaults")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Vault {

    @Id
    @Column(name = "vault_id", nullable = false)
    private UUID vaultId;

    @Column(name = "current_vault_key_version", nullable = false)
    private int currentVaultKeyVersion;

    @Column(name = "created_by_user_id", nullable = false)
    private UUID createdByUserId;

    @Column(name = "name_ciphertext", nullable = false)
    private byte[] nameCiphertext;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "name_aead_params", nullable = false, columnDefinition = "jsonb")
    private AeadParams nameAeadParams;

    @Column(name = "vault_version", nullable = false)
    private int vaultVersion;

    @Column(name = "created_at", nullable = false)
    private OffsetDateTime createdAt;

    @Column(name = "updated_at", nullable = false)
    private OffsetDateTime updatedAt;
}