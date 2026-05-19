package ru.dmitrysvirgunov.passwordmanager.vault.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import lombok.*;

import java.io.Serializable;
import java.util.UUID;

@Embeddable
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode
public class VaultBlobPartId implements Serializable {

    @Column(name = "blob_id", nullable = false)
    private UUID blobId;

    @Column(name = "part_number", nullable = false)
    private int partNumber;
}
