package ru.dmitrysvirgunov.passwordmanager.vault.entity;

import jakarta.persistence.*;
import lombok.*;
import ru.dmitrysvirgunov.passwordmanager.vault.model.SyncOpType;

import java.time.OffsetDateTime;
import java.util.UUID;

@Entity
@Table(name = "sync_log")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class SyncLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "seq", nullable = false)
    private Long seq;

    @Column(name = "vault_id")
    private UUID vaultId;

    @Column(name = "vault_ref_id")
    private UUID vaultRefId;

    @Column(name = "object_id")
    private UUID objectId;

    @Column(name = "target_user_id")
    private UUID targetUserId;

    @Column(name = "invite_id")
    private UUID inviteId;

    @Column(name = "version")
    private Integer version;

    @Column(name = "actor_user_id", nullable = false)
    private UUID actorUserId;

    @Enumerated(EnumType.STRING)
    @Column(name = "op_type", nullable = false)
    private SyncOpType opType;

    @Column(name = "created_at", nullable = false)
    private OffsetDateTime createdAt;
}
