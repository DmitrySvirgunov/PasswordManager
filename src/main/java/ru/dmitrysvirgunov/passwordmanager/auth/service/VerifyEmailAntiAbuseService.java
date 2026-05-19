package ru.dmitrysvirgunov.passwordmanager.auth.service;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import ru.dmitrysvirgunov.passwordmanager.auth.entity.AuthAttempt;
import ru.dmitrysvirgunov.passwordmanager.auth.model.AuthAttemptDecision;
import ru.dmitrysvirgunov.passwordmanager.auth.model.AuthAttemptFlow;
import ru.dmitrysvirgunov.passwordmanager.auth.model.AuthAttemptReasonCode;
import ru.dmitrysvirgunov.passwordmanager.auth.repository.AuthAttemptRepository;
import ru.dmitrysvirgunov.passwordmanager.common.exception.TooManyRequestsException;
import ru.dmitrysvirgunov.passwordmanager.config.AntiAbuseProperties;

import java.time.OffsetDateTime;
import java.util.Map;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class VerifyEmailAntiAbuseService {

    private final AuthAttemptRepository authAttemptRepository;
    private final AuthAttemptService authAttemptService;
    private final AntiAbuseProperties antiAbuseProperties;

    public void checkAndRecord(byte[] requestIpHash, byte[] userAgentHash) {
        if (!antiAbuseProperties.enabled()) {
            return;
        }

        OffsetDateTime now = OffsetDateTime.now();
        OffsetDateTime windowStart = now.minusMinutes(antiAbuseProperties.verifyEmailWindowMinutes());

        long ipAttempts = authAttemptRepository.countByFlowAndRequestIpHashAndCreatedAtAfter(
                AuthAttemptFlow.VERIFY_EMAIL,
                requestIpHash,
                windowStart
        );

        boolean ipBlocked = ipAttempts >= antiAbuseProperties.verifyEmailIpLimit();
        AuthAttemptDecision decision = ipBlocked
                ? AuthAttemptDecision.BLOCKED
                : AuthAttemptDecision.ALLOWED;

        AuthAttempt authAttempt = AuthAttempt.builder()
                .attemptId(UUID.randomUUID())
                .flow(AuthAttemptFlow.VERIFY_EMAIL)
                .userId(null)
                .emailHash(null)
                .requestIpHash(requestIpHash)
                .userAgentHash(userAgentHash)
                .decision(decision)
                .reasonCode(ipBlocked ? AuthAttemptReasonCode.IP_RATE_LIMIT : null)
                .meta(Map.of(
                        "ipAttemptsInWindow", ipAttempts,
                        "windowMinutes", antiAbuseProperties.verifyEmailWindowMinutes()
                ))
                .createdAt(now)
                .build();

        authAttemptService.save(authAttempt);

        if (decision == AuthAttemptDecision.BLOCKED) {
            throw new TooManyRequestsException(
                    "Слишком много попыток подтверждения почты с этого IP. Попробуйте позже."
            );
        }
    }
}
