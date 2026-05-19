package ru.dmitrysvirgunov.passwordmanager.vault.service;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import ru.dmitrysvirgunov.passwordmanager.common.exception.TooManyRequestsException;
import ru.dmitrysvirgunov.passwordmanager.common.security.HashingService;
import ru.dmitrysvirgunov.passwordmanager.config.AntiAbuseProperties;
import ru.dmitrysvirgunov.passwordmanager.vault.entity.VaultSharingAttempt;
import ru.dmitrysvirgunov.passwordmanager.vault.model.VaultSharingAttemptAction;
import ru.dmitrysvirgunov.passwordmanager.vault.model.VaultSharingAttemptDecision;
import ru.dmitrysvirgunov.passwordmanager.vault.repository.VaultSharingAttemptRepository;

import java.time.OffsetDateTime;
import java.util.Map;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class VaultSharingAntiAbuseService {

    private final VaultSharingAttemptRepository vaultSharingAttemptRepository;
    private final VaultSharingAttemptService vaultSharingAttemptService;
    private final HashingService hashingService;
    private final AntiAbuseProperties antiAbuseProperties;

    public void checkInviteeKeyLookupAllowed(UUID actorUserId, UUID vaultId, String targetEmail) {
        checkAllowed(
                VaultSharingAttemptAction.INVITEE_KEY_LOOKUP,
                actorUserId,
                vaultId,
                targetEmail,
                antiAbuseProperties.inviteLookupActorLimit(),
                antiAbuseProperties.inviteLookupVaultLimit(),
                antiAbuseProperties.inviteLookupTargetLimit(),
                antiAbuseProperties.inviteLookupWindowMinutes(),
                "Слишком много проверок получателя для этого сейфа. Попробуйте позже."
        );
    }

    public void checkCreateInviteAllowed(UUID actorUserId, UUID vaultId, String targetEmail) {
        checkAllowed(
                VaultSharingAttemptAction.CREATE_INVITE,
                actorUserId,
                vaultId,
                targetEmail,
                antiAbuseProperties.inviteCreateActorLimit(),
                antiAbuseProperties.inviteCreateVaultLimit(),
                antiAbuseProperties.inviteCreateTargetLimit(),
                antiAbuseProperties.inviteCreateWindowMinutes(),
                "Слишком много приглашений для этого сейфа. Попробуйте позже."
        );
    }

    private void checkAllowed(
            VaultSharingAttemptAction action,
            UUID actorUserId,
            UUID vaultId,
            String targetEmail,
            int actorLimit,
            int vaultLimit,
            int targetLimit,
            long windowMinutes,
            String blockedMessage
    ) {
        if (!antiAbuseProperties.enabled()) {
            return;
        }

        OffsetDateTime now = OffsetDateTime.now();
        OffsetDateTime windowStart = now.minusMinutes(windowMinutes);
        byte[] targetEmailHash = hashingService.hashEmailForAbuse(targetEmail);

        long actorAttempts = vaultSharingAttemptRepository.countByActionAndActorUserIdAndCreatedAtAfter(
                action,
                actorUserId,
                windowStart
        );
        long vaultAttempts = vaultSharingAttemptRepository.countByActionAndVaultIdAndCreatedAtAfter(
                action,
                vaultId,
                windowStart
        );
        long targetAttempts = vaultSharingAttemptRepository
                .countByActionAndActorUserIdAndTargetEmailHashAndCreatedAtAfter(
                        action,
                        actorUserId,
                        targetEmailHash,
                        windowStart
                );

        boolean actorBlocked = actorAttempts >= actorLimit;
        boolean vaultBlocked = vaultAttempts >= vaultLimit;
        boolean targetBlocked = targetAttempts >= targetLimit;

        VaultSharingAttempt attempt = VaultSharingAttempt.builder()
                .attemptId(UUID.randomUUID())
                .action(action)
                .actorUserId(actorUserId)
                .vaultId(vaultId)
                .targetEmailHash(targetEmailHash)
                .decision((actorBlocked || vaultBlocked || targetBlocked)
                        ? VaultSharingAttemptDecision.BLOCKED
                        : VaultSharingAttemptDecision.ALLOWED)
                .meta(Map.of(
                        "actorAttemptsInWindow", actorAttempts,
                        "vaultAttemptsInWindow", vaultAttempts,
                        "targetAttemptsInWindow", targetAttempts,
                        "windowMinutes", windowMinutes,
                        "actorBlocked", actorBlocked,
                        "vaultBlocked", vaultBlocked,
                        "targetBlocked", targetBlocked
                ))
                .createdAt(now)
                .build();

        vaultSharingAttemptService.save(attempt);

        if (attempt.getDecision() == VaultSharingAttemptDecision.BLOCKED) {
            throw new TooManyRequestsException(blockedMessage);
        }
    }
}
