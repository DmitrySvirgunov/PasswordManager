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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class RegistrationAntiAbuseServiceTest {

    @Mock
    private AuthAttemptRepository authAttemptRepository;

    @Mock
    private AuthAttemptService authAttemptService;

    @Mock
    private AntiAbuseProperties antiAbuseProperties;

    @InjectMocks
    private RegistrationAntiAbuseService registrationAntiAbuseService;

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

        registrationAntiAbuseService.checkAndRecord(emailHash, ipHash, userAgentHash);

        verifyNoInteractions(authAttemptRepository);
        verifyNoInteractions(authAttemptService);
    }

    @Test
    void shouldSaveAllowedAttemptWhenLimitsNotExceeded() {
        when(antiAbuseProperties.enabled()).thenReturn(true);
        when(antiAbuseProperties.emailLimit()).thenReturn(3);
        when(antiAbuseProperties.ipLimit()).thenReturn(10);
        when(antiAbuseProperties.emailWindowMinutes()).thenReturn(30L);
        when(antiAbuseProperties.ipWindowMinutes()).thenReturn(15L);

        when(authAttemptRepository.countByFlowAndEmailHashAndCreatedAtAfter(any(), any(), any()))
                .thenReturn(0L);
        when(authAttemptRepository.countByFlowAndRequestIpHashAndCreatedAtAfter(any(), any(), any()))
                .thenReturn(0L);

        registrationAntiAbuseService.checkAndRecord(emailHash, ipHash, userAgentHash);

        ArgumentCaptor<AuthAttempt> captor = ArgumentCaptor.forClass(AuthAttempt.class);
        verify(authAttemptService).save(captor.capture());

        AuthAttempt saved = captor.getValue();
        assertThat(saved.getDecision()).isEqualTo(AuthAttemptDecision.ALLOWED);
        assertThat(saved.getReasonCode()).isNull();
    }

    @Test
    void shouldThrowWhenEmailLimitExceeded() {
        when(antiAbuseProperties.enabled()).thenReturn(true);
        when(antiAbuseProperties.emailLimit()).thenReturn(3);
        when(antiAbuseProperties.ipLimit()).thenReturn(10);
        when(antiAbuseProperties.emailWindowMinutes()).thenReturn(30L);
        when(antiAbuseProperties.ipWindowMinutes()).thenReturn(15L);

        when(authAttemptRepository.countByFlowAndEmailHashAndCreatedAtAfter(any(), any(), any()))
                .thenReturn(3L);
        when(authAttemptRepository.countByFlowAndRequestIpHashAndCreatedAtAfter(any(), any(), any()))
                .thenReturn(0L);

        assertThatThrownBy(() ->
                registrationAntiAbuseService.checkAndRecord(emailHash, ipHash, userAgentHash)
        ).isInstanceOf(TooManyRequestsException.class)
                .hasMessage("Слишком много попыток регистрации для этого email. Попробуйте позже.");

        ArgumentCaptor<AuthAttempt> captor = ArgumentCaptor.forClass(AuthAttempt.class);
        verify(authAttemptService).save(captor.capture());

        AuthAttempt saved = captor.getValue();
        assertThat(saved.getDecision()).isEqualTo(AuthAttemptDecision.BLOCKED);
        assertThat(saved.getReasonCode()).isEqualTo(AuthAttemptReasonCode.EMAIL_RATE_LIMIT);
    }

    @Test
    void shouldThrowWhenBothLimitsExceeded() {
        when(antiAbuseProperties.enabled()).thenReturn(true);
        when(antiAbuseProperties.emailLimit()).thenReturn(3);
        when(antiAbuseProperties.ipLimit()).thenReturn(10);
        when(antiAbuseProperties.emailWindowMinutes()).thenReturn(30L);
        when(antiAbuseProperties.ipWindowMinutes()).thenReturn(15L);

        when(authAttemptRepository.countByFlowAndEmailHashAndCreatedAtAfter(any(), any(), any()))
                .thenReturn(3L);
        when(authAttemptRepository.countByFlowAndRequestIpHashAndCreatedAtAfter(any(), any(), any()))
                .thenReturn(10L);

        assertThatThrownBy(() ->
                registrationAntiAbuseService.checkAndRecord(emailHash, ipHash, userAgentHash)
        ).isInstanceOf(TooManyRequestsException.class)
                .hasMessage("Слишком много попыток регистрации для этого email и IP. Попробуйте позже.");

        ArgumentCaptor<AuthAttempt> captor = ArgumentCaptor.forClass(AuthAttempt.class);
        verify(authAttemptService).save(captor.capture());

        AuthAttempt saved = captor.getValue();
        assertThat(saved.getDecision()).isEqualTo(AuthAttemptDecision.BLOCKED);
        assertThat(saved.getReasonCode()).isEqualTo(AuthAttemptReasonCode.EMAIL_AND_IP_RATE_LIMIT);
    }
}
