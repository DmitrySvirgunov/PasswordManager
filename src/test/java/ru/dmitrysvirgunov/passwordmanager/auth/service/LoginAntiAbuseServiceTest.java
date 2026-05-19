package ru.dmitrysvirgunov.passwordmanager.auth.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import ru.dmitrysvirgunov.passwordmanager.auth.entity.AuthAttempt;
import ru.dmitrysvirgunov.passwordmanager.auth.model.AuthAttemptDecision;
import ru.dmitrysvirgunov.passwordmanager.auth.model.AuthAttemptReasonCode;
import ru.dmitrysvirgunov.passwordmanager.auth.repository.AuthAttemptRepository;
import ru.dmitrysvirgunov.passwordmanager.common.exception.TooManyRequestsException;
import ru.dmitrysvirgunov.passwordmanager.config.AntiAbuseProperties;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class LoginAntiAbuseServiceTest {

    @Mock
    private AuthAttemptRepository authAttemptRepository;

    @Mock
    private AuthAttemptService authAttemptService;

    @Mock
    private AntiAbuseProperties antiAbuseProperties;

    @InjectMocks
    private LoginAntiAbuseService loginAntiAbuseService;

    private byte[] emailHash;
    private byte[] ipHash;
    private byte[] userAgentHash;

    @BeforeEach
    void setUp() {
        emailHash = new byte[]{1, 2, 3};
        ipHash = new byte[]{4, 5, 6};
        userAgentHash = new byte[]{7, 8, 9};
    }

    @Test
    void shouldReturnImmediatelyWhenAntiAbuseDisabled() {
        when(antiAbuseProperties.enabled()).thenReturn(false);

        loginAntiAbuseService.checkAllowed(emailHash, ipHash, userAgentHash);
        loginAntiAbuseService.recordFailure(
                null,
                emailHash,
                ipHash,
                userAgentHash,
                AuthAttemptReasonCode.UNKNOWN_EMAIL
        );

        verifyNoInteractions(authAttemptRepository);
        verifyNoInteractions(authAttemptService);
    }

    @Test
    void shouldAllowLoginWhenLimitsNotExceeded() {
        when(antiAbuseProperties.enabled()).thenReturn(true);
        when(antiAbuseProperties.loginEmailLimit()).thenReturn(8);
        when(antiAbuseProperties.loginIpLimit()).thenReturn(25);
        when(antiAbuseProperties.loginEmailWindowMinutes()).thenReturn(15L);
        when(antiAbuseProperties.loginIpWindowMinutes()).thenReturn(15L);

        when(authAttemptRepository.countByFlowAndEmailHashAndCreatedAtAfter(any(), any(), any()))
                .thenReturn(0L);
        when(authAttemptRepository.countByFlowAndRequestIpHashAndCreatedAtAfter(any(), any(), any()))
                .thenReturn(0L);

        loginAntiAbuseService.checkAllowed(emailHash, ipHash, userAgentHash);

        verify(authAttemptRepository).countByFlowAndEmailHashAndCreatedAtAfter(any(), any(), any());
        verify(authAttemptRepository).countByFlowAndRequestIpHashAndCreatedAtAfter(any(), any(), any());
        verifyNoInteractions(authAttemptService);
    }

    @Test
    void shouldThrowWhenLoginEmailLimitExceeded() {
        when(antiAbuseProperties.enabled()).thenReturn(true);
        when(antiAbuseProperties.loginEmailLimit()).thenReturn(8);
        when(antiAbuseProperties.loginIpLimit()).thenReturn(25);
        when(antiAbuseProperties.loginEmailWindowMinutes()).thenReturn(15L);
        when(antiAbuseProperties.loginIpWindowMinutes()).thenReturn(15L);

        when(authAttemptRepository.countByFlowAndEmailHashAndCreatedAtAfter(any(), any(), any()))
                .thenReturn(8L);
        when(authAttemptRepository.countByFlowAndRequestIpHashAndCreatedAtAfter(any(), any(), any()))
                .thenReturn(0L);

        assertThatThrownBy(() ->
                loginAntiAbuseService.checkAllowed(emailHash, ipHash, userAgentHash)
        ).isInstanceOf(TooManyRequestsException.class)
                .hasMessage("Слишком много неудачных попыток входа для этого аккаунта. Попробуйте позже.");

        ArgumentCaptor<AuthAttempt> captor = ArgumentCaptor.forClass(AuthAttempt.class);
        verify(authAttemptService).save(captor.capture());

        AuthAttempt saved = captor.getValue();
        assertThat(saved.getDecision()).isEqualTo(AuthAttemptDecision.BLOCKED);
        assertThat(saved.getReasonCode()).isEqualTo(AuthAttemptReasonCode.LOGIN_RATE_LIMIT);
    }

    @Test
    void shouldSaveFailedAttempt() {
        when(antiAbuseProperties.enabled()).thenReturn(true);

        UUID userId = UUID.randomUUID();
        loginAntiAbuseService.recordFailure(
                userId,
                emailHash,
                ipHash,
                userAgentHash,
                AuthAttemptReasonCode.INVALID_CREDENTIALS
        );

        ArgumentCaptor<AuthAttempt> captor = ArgumentCaptor.forClass(AuthAttempt.class);
        verify(authAttemptService).save(captor.capture());

        AuthAttempt saved = captor.getValue();
        assertThat(saved.getUserId()).isEqualTo(userId);
        assertThat(saved.getDecision()).isEqualTo(AuthAttemptDecision.FAILED);
        assertThat(saved.getReasonCode()).isEqualTo(AuthAttemptReasonCode.INVALID_CREDENTIALS);
    }
}
