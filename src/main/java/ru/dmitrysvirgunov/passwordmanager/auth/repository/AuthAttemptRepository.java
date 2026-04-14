package ru.dmitrysvirgunov.passwordmanager.auth.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import ru.dmitrysvirgunov.passwordmanager.auth.entity.AuthAttempt;
import ru.dmitrysvirgunov.passwordmanager.auth.model.AuthAttemptFlow;

import java.time.OffsetDateTime;
import java.util.UUID;

public interface AuthAttemptRepository extends JpaRepository<AuthAttempt, UUID> {

    long countByFlowAndEmailHashAndCreatedAtAfter(
            AuthAttemptFlow flow,
            byte[] emailHash,
            OffsetDateTime createdAtAfter
    );

    long countByFlowAndRequestIpHashAndCreatedAtAfter(
            AuthAttemptFlow flow,
            byte[] requestIpHash,
            OffsetDateTime createdAtAfter
    );
}