package ru.dmitrysvirgunov.passwordmanager.auth.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;
import ru.dmitrysvirgunov.passwordmanager.auth.model.AuthAttemptDecision;
import ru.dmitrysvirgunov.passwordmanager.auth.model.AuthAttemptFlow;
import ru.dmitrysvirgunov.passwordmanager.auth.model.AuthAttemptReasonCode;

import java.time.OffsetDateTime;
import java.util.Map;
import java.util.UUID;

@Entity
@Table(name = "auth_attempts")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AuthAttempt {

    @Id
    @Column(name = "attempt_id", nullable = false)
    private UUID attemptId;

    @Enumerated(EnumType.STRING)
    @Column(name = "flow", nullable = false)
    private AuthAttemptFlow flow;

    @Column(name = "user_id")
    private UUID userId;

    @Column(name = "email_hash")
    private byte[] emailHash;

    @Column(name = "request_ip_hash", nullable = false)
    private byte[] requestIpHash;

    @Column(name = "user_agent_hash")
    private byte[] userAgentHash;

    @Enumerated(EnumType.STRING)
    @Column(name = "decision", nullable = false)
    private AuthAttemptDecision decision;

    @Enumerated(EnumType.STRING)
    @Column(name = "reason_code")
    private AuthAttemptReasonCode reasonCode;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "meta")
    private Map<String, Object> meta;

    @Column(name = "created_at", nullable = false)
    private OffsetDateTime createdAt;
}