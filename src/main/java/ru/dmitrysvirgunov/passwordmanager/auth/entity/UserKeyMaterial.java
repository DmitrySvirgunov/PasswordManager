package ru.dmitrysvirgunov.passwordmanager.auth.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;
import ru.dmitrysvirgunov.passwordmanager.auth.model.KeyParams;

import java.time.OffsetDateTime;
import java.util.UUID;

@Entity
@Table(name = "user_key_material")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserKeyMaterial {
    @Id
    @Column(name = "user_id", nullable = false)
    private UUID userId;

    @Column(name = "public_key", nullable = false)
    private byte[] publicKey;

    @Column(name = "encrypted_private_key", nullable = false)
    private byte[] encryptedPrivateKey;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "key_params", nullable = false)
    private KeyParams keyParams;

    @Column(name = "key_version", nullable = false)
    private int keyVersion;

    @Column(name = "created_at", nullable = false)
    private OffsetDateTime createdAt;

    @Column(name = "rotated_at")
    private OffsetDateTime rotatedAt;
}
