package ru.dmitrysvirgunov.passwordmanager.auth.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import ru.dmitrysvirgunov.passwordmanager.auth.entity.UserSession;

import java.util.Optional;
import java.util.UUID;

public interface UserSessionRepository extends JpaRepository<UserSession, UUID> {

    Optional<UserSession> findByRefreshTokenHashAndRevokedAtIsNull(byte[] refreshTokenHash);
}