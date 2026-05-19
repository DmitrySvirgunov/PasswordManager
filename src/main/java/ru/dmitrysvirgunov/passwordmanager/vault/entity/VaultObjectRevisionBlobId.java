package ru.dmitrysvirgunov.passwordmanager.vault.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import lombok.*;
import ru.dmitrysvirgunov.passwordmanager.vault.model.VaultBlobReferenceRole;

import java.io.Serializable;
import java.util.UUID;

@Embeddable
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode
public class VaultObjectRevisionBlobId implements Serializable {

    @Column(name = "revision_id", nullable = false)
    private UUID revisionId;

    @Enumerated(EnumType.STRING)
    @Column(name = "role", nullable = false)
    private VaultBlobReferenceRole role;
}
