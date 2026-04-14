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

import java.time.OffsetDateTime;
import java.util.UUID;

@Entity
@Table(name = "user_auth")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserAuth {

    @Id
    @Column(name = "user_id", nullable = false)
    private UUID userId;

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

    @Column(name = "auth_version", nullable = false)
    private int authVersion;

    @Column(name = "password_changed_at", nullable = false)
    private OffsetDateTime passwordChangedAt;

    @Column(name = "updated_at", nullable = false)
    private OffsetDateTime updatedAt;
}
