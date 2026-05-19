package ru.dmitrysvirgunov.passwordmanager.auth.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
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
public class RegistrationAntiAbuseService {

    private final AuthAttemptRepository authAttemptRepository;
    private final AuthAttemptService authAttemptService;
    private final AntiAbuseProperties antiAbuseProperties;

    public void checkAndRecord(byte[] emailHash, byte[] requestIpHash, byte[] userAgentHash) {
        if (!antiAbuseProperties.enabled()) {
            return;
        }

        OffsetDateTime now = OffsetDateTime.now();

        long emailAttempts = authAttemptRepository.countByFlowAndEmailHashAndCreatedAtAfter(
                AuthAttemptFlow.REGISTER,
                emailHash,
                now.minusMinutes(antiAbuseProperties.emailWindowMinutes())
        );

        long ipAttempts = authAttemptRepository.countByFlowAndRequestIpHashAndCreatedAtAfter(
                AuthAttemptFlow.REGISTER,
                requestIpHash,
                now.minusMinutes(antiAbuseProperties.ipWindowMinutes())
        );

        boolean emailBlocked = emailAttempts >= antiAbuseProperties.emailLimit();
        boolean ipBlocked = ipAttempts >= antiAbuseProperties.ipLimit();

        AuthAttemptDecision decision = resolveDecision(emailBlocked, ipBlocked);
        AuthAttemptReasonCode reasonCode = resolveReasonCode(emailBlocked, ipBlocked);

        AuthAttempt authAttempt = AuthAttempt.builder()
                .attemptId(UUID.randomUUID())
                .flow(AuthAttemptFlow.REGISTER)
                .userId(null)
                .emailHash(emailHash)
                .requestIpHash(requestIpHash)
                .userAgentHash(userAgentHash)
                .decision(decision)
                .reasonCode(reasonCode)
                .meta(Map.of(
                        "emailAttemptsInWindow", emailAttempts,
                        "ipAttemptsInWindow", ipAttempts,
                        "emailWindowMinutes", antiAbuseProperties.emailWindowMinutes(),
                        "ipWindowMinutes", antiAbuseProperties.ipWindowMinutes()
                ))
                .createdAt(now)
                .build();

        authAttemptService.save(authAttempt);

        if (decision == AuthAttemptDecision.BLOCKED) {
            throw new TooManyRequestsException(buildMessage(reasonCode));
        }
    }

    private AuthAttemptDecision resolveDecision(boolean emailBlocked, boolean ipBlocked) {
        return (emailBlocked || ipBlocked)
                ? AuthAttemptDecision.BLOCKED
                : AuthAttemptDecision.ALLOWED;
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

    private String buildMessage(AuthAttemptReasonCode reasonCode) {
        if (reasonCode == AuthAttemptReasonCode.EMAIL_AND_IP_RATE_LIMIT) {
            return "Слишком много попыток регистрации для этого email и IP. Попробуйте позже.";
        }
        if (reasonCode == AuthAttemptReasonCode.EMAIL_RATE_LIMIT) {
            return "Слишком много попыток регистрации для этого email. Попробуйте позже.";
        }
        if (reasonCode == AuthAttemptReasonCode.IP_RATE_LIMIT) {
            return "Слишком много попыток регистрации с этого IP. Попробуйте позже.";
        }
        return "Слишком много попыток регистрации. Попробуйте позже.";
    }
}
