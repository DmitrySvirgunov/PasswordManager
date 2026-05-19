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
import ru.dmitrysvirgunov.passwordmanager.auth.model.AuthAttemptFlow;
import ru.dmitrysvirgunov.passwordmanager.auth.model.AuthAttemptReasonCode;
import ru.dmitrysvirgunov.passwordmanager.auth.repository.AuthAttemptRepository;
import ru.dmitrysvirgunov.passwordmanager.common.exception.TooManyRequestsException;
import ru.dmitrysvirgunov.passwordmanager.config.AntiAbuseProperties;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class PreloginAntiAbuseServiceTest {

    @Mock
    private AuthAttemptRepository authAttemptRepository;

    @Mock
    private AuthAttemptService authAttemptService;

    @Mock
    private AntiAbuseProperties antiAbuseProperties;

    @InjectMocks
    private PreloginAntiAbuseService preloginAntiAbuseService;

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

        preloginAntiAbuseService.checkAndRecord(emailHash, ipHash, userAgentHash);

        verifyNoInteractions(authAttemptRepository);
        verifyNoInteractions(authAttemptService);
    }

    @Test
    void shouldSaveAllowedAttemptWhenLimitsNotExceeded() {
        when(antiAbuseProperties.enabled()).thenReturn(true);
        when(antiAbuseProperties.preloginEmailLimit()).thenReturn(30);
        when(antiAbuseProperties.preloginIpLimit()).thenReturn(120);
        when(antiAbuseProperties.preloginWindowMinutes()).thenReturn(15L);
        when(authAttemptRepository.countByFlowAndEmailHashAndCreatedAtAfter(any(), any(), any()))
                .thenReturn(0L);
        when(authAttemptRepository.countByFlowAndRequestIpHashAndCreatedAtAfter(any(), any(), any()))
                .thenReturn(0L);

        preloginAntiAbuseService.checkAndRecord(emailHash, ipHash, userAgentHash);

        ArgumentCaptor<AuthAttempt> captor = ArgumentCaptor.forClass(AuthAttempt.class);
        verify(authAttemptService).save(captor.capture());

        AuthAttempt saved = captor.getValue();
        assertThat(saved.getFlow()).isEqualTo(AuthAttemptFlow.PRELOGIN);
        assertThat(saved.getDecision()).isEqualTo(AuthAttemptDecision.ALLOWED);
        assertThat(saved.getReasonCode()).isNull();
    }

    @Test
    void shouldThrowWhenIpLimitExceeded() {
        when(antiAbuseProperties.enabled()).thenReturn(true);
        when(antiAbuseProperties.preloginEmailLimit()).thenReturn(30);
        when(antiAbuseProperties.preloginIpLimit()).thenReturn(120);
        when(antiAbuseProperties.preloginWindowMinutes()).thenReturn(15L);
        when(authAttemptRepository.countByFlowAndEmailHashAndCreatedAtAfter(any(), any(), any()))
                .thenReturn(0L);
        when(authAttemptRepository.countByFlowAndRequestIpHashAndCreatedAtAfter(any(), any(), any()))
                .thenReturn(120L);

        assertThatThrownBy(() ->
                preloginAntiAbuseService.checkAndRecord(emailHash, ipHash, userAgentHash)
        ).isInstanceOf(TooManyRequestsException.class)
                .hasMessage("Слишком много запросов подготовки входа с этого IP. Попробуйте позже.");

        ArgumentCaptor<AuthAttempt> captor = ArgumentCaptor.forClass(AuthAttempt.class);
        verify(authAttemptService).save(captor.capture());

        AuthAttempt saved = captor.getValue();
        assertThat(saved.getDecision()).isEqualTo(AuthAttemptDecision.BLOCKED);
        assertThat(saved.getReasonCode()).isEqualTo(AuthAttemptReasonCode.IP_RATE_LIMIT);
    }
}
