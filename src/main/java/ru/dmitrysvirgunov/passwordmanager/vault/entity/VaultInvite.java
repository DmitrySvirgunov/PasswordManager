package ru.dmitrysvirgunov.passwordmanager.vault.entity;

import jakarta.persistence.*;
import lombok.*;
import ru.dmitrysvirgunov.passwordmanager.vault.model.VaultInviteStatus;
import ru.dmitrysvirgunov.passwordmanager.vault.model.VaultMemberRole;

import java.time.OffsetDateTime;
import java.util.UUID;

@Entity
@Table(name = "vault_invites")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class VaultInvite {

    @Id
    @Column(name = "invite_id", nullable = false)
    private UUID inviteId;

    @Column(name = "vault_id", nullable = false)
    private UUID vaultId;

    @Column(name = "created_by_user_id", nullable = false)
    private UUID createdByUserId;

    @Column(name = "invitee_user_id", nullable = false)
    private UUID inviteeUserId;

    @Column(name = "invitee_email", nullable = false)
    private String inviteeEmail;

    @Enumerated(EnumType.STRING)
    @Column(name = "role", nullable = false)
    private VaultMemberRole role;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false)
    private VaultInviteStatus status;

    @Column(name = "created_at", nullable = false)
    private OffsetDateTime createdAt;

    @Column(name = "expires_at", nullable = false)
    private OffsetDateTime expiresAt;

    @Column(name = "accepted_at")
    private OffsetDateTime acceptedAt;

    @Column(name = "revoked_at")
    private OffsetDateTime revokedAt;
}