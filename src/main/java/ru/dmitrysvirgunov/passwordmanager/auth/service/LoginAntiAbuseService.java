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
public class LoginAntiAbuseService {

    private final AuthAttemptRepository authAttemptRepository;
    private final AuthAttemptService authAttemptService;
    private final AntiAbuseProperties antiAbuseProperties;

    public void checkAllowed(byte[] emailHash, byte[] requestIpHash, byte[] userAgentHash) {
        if (!antiAbuseProperties.enabled()) {
            return;
        }

        OffsetDateTime now = OffsetDateTime.now();

        long emailAttempts = authAttemptRepository.countByFlowAndEmailHashAndCreatedAtAfter(
                AuthAttemptFlow.LOGIN,
                emailHash,
                now.minusMinutes(antiAbuseProperties.loginEmailWindowMinutes())
        );

        long ipAttempts = authAttemptRepository.countByFlowAndRequestIpHashAndCreatedAtAfter(
                AuthAttemptFlow.LOGIN,
                requestIpHash,
                now.minusMinutes(antiAbuseProperties.loginIpWindowMinutes())
        );

        boolean emailBlocked = emailAttempts >= antiAbuseProperties.loginEmailLimit();
        boolean ipBlocked = ipAttempts >= antiAbuseProperties.loginIpLimit();

        if (!emailBlocked && !ipBlocked) {
            return;
        }

        AuthAttempt authAttempt = AuthAttempt.builder()
                .attemptId(UUID.randomUUID())
                .flow(AuthAttemptFlow.LOGIN)
                .userId(null)
                .emailHash(emailHash)
                .requestIpHash(requestIpHash)
                .userAgentHash(userAgentHash)
                .decision(AuthAttemptDecision.BLOCKED)
                .reasonCode(AuthAttemptReasonCode.LOGIN_RATE_LIMIT)
                .meta(Map.of(
                        "emailAttemptsInWindow", emailAttempts,
                        "ipAttemptsInWindow", ipAttempts,
                        "emailWindowMinutes", antiAbuseProperties.loginEmailWindowMinutes(),
                        "ipWindowMinutes", antiAbuseProperties.loginIpWindowMinutes(),
                        "emailBlocked", emailBlocked,
                        "ipBlocked", ipBlocked
                ))
                .createdAt(now)
                .build();

        authAttemptService.save(authAttempt);
        throw new TooManyRequestsException(buildBlockedMessage(emailBlocked, ipBlocked));
    }

    public void recordFailure(
            UUID userId,
            byte[] emailHash,
            byte[] requestIpHash,
            byte[] userAgentHash,
            AuthAttemptReasonCode reasonCode
    ) {
        if (!antiAbuseProperties.enabled()) {
            return;
        }

        AuthAttempt authAttempt = AuthAttempt.builder()
                .attemptId(UUID.randomUUID())
                .flow(AuthAttemptFlow.LOGIN)
                .userId(userId)
                .emailHash(emailHash)
                .requestIpHash(requestIpHash)
                .userAgentHash(userAgentHash)
                .decision(AuthAttemptDecision.FAILED)
                .reasonCode(reasonCode)
                .meta(Map.of("failureReason", reasonCode.name()))
                .createdAt(OffsetDateTime.now())
                .build();

        authAttemptService.save(authAttempt);
    }

    private String buildBlockedMessage(boolean emailBlocked, boolean ipBlocked) {
        if (emailBlocked && ipBlocked) {
            return "Слишком много неудачных попыток входа для этого аккаунта и IP. Попробуйте позже.";
        }

        if (emailBlocked) {
            return "Слишком много неудачных попыток входа для этого аккаунта. Попробуйте позже.";
        }

        return "Слишком много неудачных попыток входа с этого IP. Попробуйте позже.";
    }
}
