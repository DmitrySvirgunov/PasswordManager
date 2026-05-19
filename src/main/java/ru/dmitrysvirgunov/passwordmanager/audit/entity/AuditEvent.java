package ru.dmitrysvirgunov.passwordmanager.audit.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;
import ru.dmitrysvirgunov.passwordmanager.audit.model.AuditScopeType;
import tools.jackson.databind.JsonNode;

import java.time.OffsetDateTime;
import java.util.UUID;

@Entity
@Table(name = "audit_events")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AuditEvent {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "event_id", nullable = false)
    private Long eventId;

    @Column(name = "actor_user_id")
    private UUID actorUserId;

    @Enumerated(EnumType.STRING)
    @Column(name = "scope_type", nullable = false)
    private AuditScopeType scopeType;

    @Column(name = "scope_id", nullable = false)
    private UUID scopeId;

    @Column(name = "event_type", nullable = false)
    private String eventType;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "meta", columnDefinition = "jsonb")
    private JsonNode meta;

    @Column(name = "event_hash", nullable = false)
    private byte[] eventHash;

    @Column(name = "prev_event_hash")
    private byte[] prevEventHash;

    @Column(name = "signature_key_id", nullable = false)
    private String signatureKeyId;

    @Column(name = "event_signature", nullable = false)
    private byte[] eventSignature;

    @Column(name = "created_at", nullable = false)
    private OffsetDateTime createdAt;
}