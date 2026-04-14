package ru.dmitrysvirgunov.passwordmanager.auth.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import ru.dmitrysvirgunov.passwordmanager.auth.entity.PendingRegistration;

import java.util.Optional;
import java.util.UUID;

public interface PendingRegistrationRepository extends JpaRepository<PendingRegistration, UUID> {

    Optional<PendingRegistration> findByEmailIgnoreCaseAndUsedAtIsNull(String email);

    Optional<PendingRegistration> findByTokenHashAndUsedAtIsNull(byte[] tokenHash);
}