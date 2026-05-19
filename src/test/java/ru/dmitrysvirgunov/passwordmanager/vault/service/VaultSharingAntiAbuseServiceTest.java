package ru.dmitrysvirgunov.passwordmanager.vault.service;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import ru.dmitrysvirgunov.passwordmanager.common.exception.TooManyRequestsException;
import ru.dmitrysvirgunov.passwordmanager.common.security.HashingService;
import ru.dmitrysvirgunov.passwordmanager.config.AntiAbuseProperties;
import ru.dmitrysvirgunov.passwordmanager.vault.entity.VaultSharingAttempt;
import ru.dmitrysvirgunov.passwordmanager.vault.model.VaultSharingAttemptAction;
import ru.dmitrysvirgunov.passwordmanager.vault.model.VaultSharingAttemptDecision;
import ru.dmitrysvirgunov.passwordmanager.vault.repository.VaultSharingAttemptRepository;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class VaultSharingAntiAbuseServiceTest {

    @Mock
    private VaultSharingAttemptRepository vaultSharingAttemptRepository;

    @Mock
    private VaultSharingAttemptService vaultSharingAttemptService;

    @Mock
    private HashingService hashingService;

    @Mock
    private AntiAbuseProperties antiAbuseProperties;

    @InjectMocks
    private VaultSharingAntiAbuseService vaultSharingAntiAbuseService;

    @Test
    void shouldReturnImmediatelyWhenAntiAbuseDisabled() {
        when(antiAbuseProperties.enabled()).thenReturn(false);

        vaultSharingAntiAbuseService.checkCreateInviteAllowed(
                UUID.randomUUID(),
                UUID.randomUUID(),
                "teammate@example.com"
        );

        verifyNoInteractions(vaultSharingAttemptRepository);
        verifyNoInteractions(vaultSharingAttemptService);
        verifyNoInteractions(hashingService);
    }

    @Test
    void shouldSaveAllowedInviteLookupAttempt() {
        UUID actorUserId = UUID.randomUUID();
        UUID vaultId = UUID.randomUUID();
        byte[] targetEmailHash = new byte[]{1, 2, 3};

        when(antiAbuseProperties.enabled()).thenReturn(true);
        when(antiAbuseProperties.inviteLookupActorLimit()).thenReturn(60);
        when(antiAbuseProperties.inviteLookupVaultLimit()).thenReturn(100);
        when(antiAbuseProperties.inviteLookupTargetLimit()).thenReturn(10);
        when(antiAbuseProperties.inviteLookupWindowMinutes()).thenReturn(15L);
        when(hashingService.hashEmailForAbuse("teammate@example.com")).thenReturn(targetEmailHash);
        when(vaultSharingAttemptRepository.countByActionAndActorUserIdAndCreatedAtAfter(any(), any(), any()))
                .thenReturn(0L);
        when(vaultSharingAttemptRepository.countByActionAndVaultIdAndCreatedAtAfter(any(), any(), any()))
                .thenReturn(0L);
        when(vaultSharingAttemptRepository.countByActionAndActorUserIdAndTargetEmailHashAndCreatedAtAfter(
                any(),
                any(),
                any(),
                any()
        )).thenReturn(0L);

        vaultSharingAntiAbuseService.checkInviteeKeyLookupAllowed(
                actorUserId,
                vaultId,
                "teammate@example.com"
        );

        ArgumentCaptor<VaultSharingAttempt> captor = ArgumentCaptor.forClass(VaultSharingAttempt.class);
        verify(vaultSharingAttemptService).save(captor.capture());

        VaultSharingAttempt saved = captor.getValue();
        assertThat(saved.getAction()).isEqualTo(VaultSharingAttemptAction.INVITEE_KEY_LOOKUP);
        assertThat(saved.getDecision()).isEqualTo(VaultSharingAttemptDecision.ALLOWED);
    }

    @Test
    void shouldThrowWhenInviteTargetLimitExceeded() {
        UUID actorUserId = UUID.randomUUID();
        UUID vaultId = UUID.randomUUID();
        byte[] targetEmailHash = new byte[]{1, 2, 3};

        when(antiAbuseProperties.enabled()).thenReturn(true);
        when(antiAbuseProperties.inviteCreateActorLimit()).thenReturn(12);
        when(antiAbuseProperties.inviteCreateVaultLimit()).thenReturn(20);
        when(antiAbuseProperties.inviteCreateTargetLimit()).thenReturn(3);
        when(antiAbuseProperties.inviteCreateWindowMinutes()).thenReturn(60L);
        when(hashingService.hashEmailForAbuse("teammate@example.com")).thenReturn(targetEmailHash);
        when(vaultSharingAttemptRepository.countByActionAndActorUserIdAndCreatedAtAfter(any(), any(), any()))
                .thenReturn(0L);
        when(vaultSharingAttemptRepository.countByActionAndVaultIdAndCreatedAtAfter(any(), any(), any()))
                .thenReturn(0L);
        when(vaultSharingAttemptRepository.countByActionAndActorUserIdAndTargetEmailHashAndCreatedAtAfter(
                any(),
                any(),
                any(),
                any()
        )).thenReturn(3L);

        assertThatThrownBy(() ->
                vaultSharingAntiAbuseService.checkCreateInviteAllowed(
                        actorUserId,
                        vaultId,
                        "teammate@example.com"
                )
        ).isInstanceOf(TooManyRequestsException.class)
                .hasMessage("Слишком много приглашений для этого сейфа. Попробуйте позже.");

        ArgumentCaptor<VaultSharingAttempt> captor = ArgumentCaptor.forClass(VaultSharingAttempt.class);
        verify(vaultSharingAttemptService).save(captor.capture());

        VaultSharingAttempt saved = captor.getValue();
        assertThat(saved.getAction()).isEqualTo(VaultSharingAttemptAction.CREATE_INVITE);
        assertThat(saved.getDecision()).isEqualTo(VaultSharingAttemptDecision.BLOCKED);
    }
}
