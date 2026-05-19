package ru.dmitrysvirgunov.passwordmanager.audit.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;
import ru.dmitrysvirgunov.passwordmanager.audit.model.AuditScopeType;
import tools.jackson.databind.JsonNode;

import java.time.OffsetDateTime;
import java.util.UUID;

@Entity
@Table(name = "audit_anchor_outbox")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AuditAnchorOutbox {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "outbox_id", nullable = false)
    private Long outboxId;

    @Column(name = "source_instance_id", nullable = false)
    private String sourceInstanceId;

    @Enumerated(EnumType.STRING)
    @Column(name = "scope_type", nullable = false)
    private AuditScopeType scopeType;

    @Column(name = "scope_id", nullable = false)
    private UUID scopeId;

    @Column(name = "event_id", nullable = false)
    private Long eventId;

    @Column(name = "event_hash", nullable = false)
    private byte[] eventHash;

    @Column(name = "event_created_at", nullable = false)
    private OffsetDateTime eventCreatedAt;

    @Column(name = "anchored_at", nullable = false)
    private OffsetDateTime anchoredAt;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "anchor_payload", nullable = false, columnDefinition = "jsonb")
    private JsonNode anchorPayload;

    @Column(name = "anchor_key_id", nullable = false)
    private String anchorKeyId;

    @Column(name = "anchor_signature", nullable = false)
    private byte[] anchorSignature;

    @Column(name = "created_at", nullable = false)
    private OffsetDateTime createdAt;

    @Column(name = "exported_at")
    private OffsetDateTime exportedAt;

    @Column(name = "export_attempts", nullable = false)
    private int exportAttempts;

    @Column(name = "last_error")
    private String lastError;
}
