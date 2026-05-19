package ru.dmitrysvirgunov.passwordmanager.audit.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.IdClass;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import ru.dmitrysvirgunov.passwordmanager.audit.model.AuditScopeType;

import java.time.OffsetDateTime;
import java.util.UUID;

@Entity
@Table(name = "audit_scope_heads")
@IdClass(AuditScopeHeadId.class)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AuditScopeHead {

    @Id
    @Enumerated(EnumType.STRING)
    @Column(name = "scope_type", nullable = false)
    private AuditScopeType scopeType;

    @Id
    @Column(name = "scope_id", nullable = false)
    private UUID scopeId;

    @Column(name = "head_event_id", nullable = false)
    private Long headEventId;

    @Column(name = "head_event_hash", nullable = false)
    private byte[] headEventHash;

    @Column(name = "head_created_at", nullable = false)
    private OffsetDateTime headCreatedAt;

    @Column(name = "updated_at", nullable = false)
    private OffsetDateTime updatedAt;
}
