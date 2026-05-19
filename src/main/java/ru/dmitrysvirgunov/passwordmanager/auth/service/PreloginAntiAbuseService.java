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
public class PreloginAntiAbuseService {

    private final AuthAttemptRepository authAttemptRepository;
    private final AuthAttemptService authAttemptService;
    private final AntiAbuseProperties antiAbuseProperties;

    public void checkAndRecord(byte[] emailHash, byte[] requestIpHash, byte[] userAgentHash) {
        if (!antiAbuseProperties.enabled()) {
            return;
        }

        OffsetDateTime now = OffsetDateTime.now();
        OffsetDateTime windowStart = now.minusMinutes(antiAbuseProperties.preloginWindowMinutes());

        long emailAttempts = authAttemptRepository.countByFlowAndEmailHashAndCreatedAtAfter(
                AuthAttemptFlow.PRELOGIN,
                emailHash,
                windowStart
        );

        long ipAttempts = authAttemptRepository.countByFlowAndRequestIpHashAndCreatedAtAfter(
                AuthAttemptFlow.PRELOGIN,
                requestIpHash,
                windowStart
        );

        boolean emailBlocked = emailAttempts >= antiAbuseProperties.preloginEmailLimit();
        boolean ipBlocked = ipAttempts >= antiAbuseProperties.preloginIpLimit();

        AuthAttemptDecision decision = (emailBlocked || ipBlocked)
                ? AuthAttemptDecision.BLOCKED
                : AuthAttemptDecision.ALLOWED;
        AuthAttemptReasonCode reasonCode = resolveReasonCode(emailBlocked, ipBlocked);

        AuthAttempt authAttempt = AuthAttempt.builder()
                .attemptId(UUID.randomUUID())
                .flow(AuthAttemptFlow.PRELOGIN)
                .userId(null)
                .emailHash(emailHash)
                .requestIpHash(requestIpHash)
                .userAgentHash(userAgentHash)
                .decision(decision)
                .reasonCode(reasonCode)
                .meta(Map.of(
                        "emailAttemptsInWindow", emailAttempts,
                        "ipAttemptsInWindow", ipAttempts,
                        "windowMinutes", antiAbuseProperties.preloginWindowMinutes()
                ))
                .createdAt(now)
                .build();

        authAttemptService.save(authAttempt);

        if (decision == AuthAttemptDecision.BLOCKED) {
            throw new TooManyRequestsException(buildMessage(emailBlocked, ipBlocked));
        }
    }

    private AuthAttemptReasonCode resolveReasonCode(boolean emailBlocked, boolean ipBlocked) {
        if (emailBlocked && ipBlocked) {
            return AuthAttemptReasonCode.EMAIL_AND_IP_RATE_LIMIT;
        }
        if (emailBlocked) {
            return AuthAttemptReasonCode.EMAIL_RATE_LIMIT;
        }
        if (ipBlocked) {
            return AuthAttemptReasonCode.IP_RATE_LIMIT;
        }
        return null;
    }

    private String buildMessage(boolean emailBlocked, boolean ipBlocked) {
        if (emailBlocked && ipBlocked) {
            return "Слишком много запросов подготовки входа для этого email и IP. Попробуйте позже.";
        }
        if (emailBlocked) {
            return "Слишком много запросов подготовки входа для этого email. Попробуйте позже.";
        }
        if (ipBlocked) {
            return "Слишком много запросов подготовки входа с этого IP. Попробуйте позже.";
        }
        return "Слишком много запросов подготовки входа. Попробуйте позже.";
    }
}
