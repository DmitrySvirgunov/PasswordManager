package ru.dmitrysvirgunov.passwordmanager.auth.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import ru.dmitrysvirgunov.passwordmanager.auth.entity.UserSession;

import java.time.OffsetDateTime;
import java.util.Optional;
import java.util.UUID;

public interface UserSessionRepository extends JpaRepository<UserSession, UUID> {

    Optional<UserSession> findByRefreshTokenHashAndRevokedAtIsNull(byte[] refreshTokenHash);

    @Modifying
    @Query("""
            update UserSession session
            set session.revokedAt = :revokedAt
            where session.userId = :userId
              and session.revokedAt is null
            """)
    int revokeAllActiveSessionsByUserId(
            @Param("userId") UUID userId,
            @Param("revokedAt") OffsetDateTime revokedAt
    );
}
