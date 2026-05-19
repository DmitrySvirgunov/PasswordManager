package ru.dmitrysvirgunov.passwordmanager.auth.repository;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import ru.dmitrysvirgunov.passwordmanager.auth.entity.AuthAttempt;
import ru.dmitrysvirgunov.passwordmanager.auth.model.AuthAttemptDecision;
import ru.dmitrysvirgunov.passwordmanager.auth.model.AuthAttemptFlow;
import ru.dmitrysvirgunov.passwordmanager.support.AbstractPostgresIntegrationTest;

import java.time.OffsetDateTime;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class AuthAttemptRepositoryIT extends AbstractPostgresIntegrationTest {

    @Autowired
    private AuthAttemptRepository authAttemptRepository;

    @Test
    void shouldCountAttemptsByEmailHashWithinWindow() {
        byte[] emailHash = new byte[]{1, 2, 3};
        byte[] ipHash = new byte[]{4, 5, 6};

        authAttemptRepository.save(AuthAttempt.builder()
                .attemptId(UUID.randomUUID())
                .flow(AuthAttemptFlow.REGISTER)
                .emailHash(emailHash)
                .requestIpHash(ipHash)
                .decision(AuthAttemptDecision.ALLOWED)
                .createdAt(OffsetDateTime.now().minusMinutes(5))
                .build());

        authAttemptRepository.save(AuthAttempt.builder()
                .attemptId(UUID.randomUUID())
                .flow(AuthAttemptFlow.REGISTER)
                .emailHash(emailHash)
                .requestIpHash(ipHash)
                .decision(AuthAttemptDecision.ALLOWED)
                .createdAt(OffsetDateTime.now().minusMinutes(1))
                .build());

        long count = authAttemptRepository.countByFlowAndEmailHashAndCreatedAtAfter(
                AuthAttemptFlow.REGISTER,
                emailHash,
                OffsetDateTime.now().minusMinutes(10)
        );

        assertThat(count).isEqualTo(2);
    }
}