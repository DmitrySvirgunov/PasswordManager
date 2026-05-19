package ru.dmitrysvirgunov.passwordmanager.auth.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;
import ru.dmitrysvirgunov.passwordmanager.common.model.AeadParams;
import ru.dmitrysvirgunov.passwordmanager.auth.model.AsymmetricKeyParams;
import ru.dmitrysvirgunov.passwordmanager.auth.model.AuthHashParams;
import ru.dmitrysvirgunov.passwordmanager.auth.model.KdfParams;

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
    @Column(name = "auth_hash_params", nullable = false, columnDefinition = "jsonb")
    private AuthHashParams authHashParams;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "client_kdf_params", nullable = false, columnDefinition = "jsonb")
    private KdfParams clientKdfParams;

    @Column(name = "wrapped_account_root_key", nullable = false)
    private byte[] wrappedAccountRootKey;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "account_root_wrap_params", nullable = false, columnDefinition = "jsonb")
    private AeadParams accountRootWrapParams;

    @Column(name = "account_root_version", nullable = false)
    private int accountRootVersion;

    @Column(name = "public_encryption_key", nullable = false)
    private byte[] publicEncryptionKey;

    @Column(name = "encrypted_private_encryption_key", nullable = false)
    private byte[] encryptedPrivateEncryptionKey;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "encryption_key_params", nullable = false, columnDefinition = "jsonb")
    private AsymmetricKeyParams encryptionKeyParams;

    @Column(name = "encryption_key_version", nullable = false)
    private int encryptionKeyVersion;

    @Column(name = "public_signing_key", nullable = false)
    private byte[] publicSigningKey;

    @Column(name = "encrypted_private_signing_key", nullable = false)
    private byte[] encryptedPrivateSigningKey;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "signing_key_params", nullable = false, columnDefinition = "jsonb")
    private AsymmetricKeyParams signingKeyParams;

    @Column(name = "signing_key_version", nullable = false)
    private int signingKeyVersion;

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