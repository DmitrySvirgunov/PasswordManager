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
public class VaultMemberId implements Serializable {

    @Column(name = "vault_id", nullable = false)
    private UUID vaultId;

    @Column(name = "user_id", nullable = false)
    private UUID userId;
}