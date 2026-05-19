package ru.dmitrysvirgunov.passwordmanager.vault.entity;

import jakarta.persistence.*;
import lombok.*;
import ru.dmitrysvirgunov.passwordmanager.vault.model.VaultMemberRole;
import ru.dmitrysvirgunov.passwordmanager.vault.model.VaultMemberStatus;

import java.time.OffsetDateTime;

@Entity
@Table(name = "vault_members")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class VaultMember {

    @EmbeddedId
    private VaultMemberId id;

    @Enumerated(EnumType.STRING)
    @Column(name = "role", nullable = false)
    private VaultMemberRole role;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false)
    private VaultMemberStatus status;

    @Column(name = "joined_at", nullable = false)
    private OffsetDateTime joinedAt;

    @Column(name = "revoked_at")
    private OffsetDateTime revokedAt;

    @Column(name = "expires_at")
    private OffsetDateTime expiresAt;
}