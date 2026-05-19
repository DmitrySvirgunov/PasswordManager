package ru.dmitrysvirgunov.passwordmanager.vault.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.*;

import java.time.OffsetDateTime;
import java.util.UUID;

@Entity
@Table(name = "vault_objects")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class VaultObject {

    @Id
    @Column(name = "object_id", nullable = false)
    private UUID objectId;

    @Column(name = "vault_id", nullable = false)
    private UUID vaultId;

    @Column(name = "current_version", nullable = false)
    private int currentVersion;

    @Column(name = "deleted", nullable = false)
    private boolean deleted;

    @Column(name = "created_at", nullable = false)
    private OffsetDateTime createdAt;

    @Column(name = "updated_at", nullable = false)
    private OffsetDateTime updatedAt;
}