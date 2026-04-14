package ru.dmitrysvirgunov.passwordmanager.auth.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;
import ru.dmitrysvirgunov.passwordmanager.auth.model.AuthHashParams;
import ru.dmitrysvirgunov.passwordmanager.auth.model.KdfParams;
import ru.dmitrysvirgunov.passwordmanager.auth.model.KeyParams;

import java.time.OffsetDateTime;
import java.util.UUID;

@Entity
@Table(name = "pending_registrations")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class PendingRegistration {

    @Id
    @Column(name = "pending_registration_id", nullable = false)
    private UUID pendingRegistrationId;

    @Column(name = "email", nullable = false)
    private String email;

    @Column(name = "auth_hash", nullable = false)
    private byte[] authHash;

    @Column(name = "auth_salt", nullable = false)
    private byte[] authSalt;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "auth_hash_params", nullable = false)
    private AuthHashParams authHashParams;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "client_kdf_params", nullable = false)
    private KdfParams clientKdfParams;

    @Column(name = "public_key", nullable = false)
    private byte[] publicKey;

    @Column(name = "encrypted_private_key", nullable = false)
    private byte[] encryptedPrivateKey;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "key_params", nullable = false)
    private KeyParams keyParams;

    @Column(name = "token_hash", nullable = false)
    private byte[] tokenHash;

    @Column(name = "request_ip_hash")
    private byte[] requestIpHash;

    @Column(name = "user_agent_hash")
    private byte[] userAgentHash;

    @Column(name = "expires_at", nullable = false)
    private OffsetDateTime expiresAt;

    @Column(name = "created_at", nullable = false)
    private OffsetDateTime createdAt;

    @Column(name = "updated_at", nullable = false)
    private OffsetDateTime updatedAt;

    @Column(name = "used_at")
    private OffsetDateTime usedAt;
}
