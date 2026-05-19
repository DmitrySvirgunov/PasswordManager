package ru.dmitrysvirgunov.passwordmanager.auth.service;

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
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class VerifyEmailAntiAbuseServiceTest {

    @Mock
    private AuthAttemptRepository authAttemptRepository;

    @Mock
    private AuthAttemptService authAttemptService;

    @Mock
    private AntiAbuseProperties antiAbuseProperties;

    @InjectMocks
    private VerifyEmailAntiAbuseService verifyEmailAntiAbuseService;

    @Test
    void shouldThrowWhenVerifyEmailIpLimitExceeded() {
        byte[] ipHash = new byte[]{4, 5, 6};
        byte[] userAgentHash = new byte[]{7, 8, 9};

        when(antiAbuseProperties.enabled()).thenReturn(true);
        when(antiAbuseProperties.verifyEmailIpLimit()).thenReturn(20);
        when(antiAbuseProperties.verifyEmailWindowMinutes()).thenReturn(15L);
        when(authAttemptRepository.countByFlowAndRequestIpHashAndCreatedAtAfter(any(), any(), any()))
                .thenReturn(20L);

        assertThatThrownBy(() ->
                verifyEmailAntiAbuseService.checkAndRecord(ipHash, userAgentHash)
        ).isInstanceOf(TooManyRequestsException.class)
                .hasMessage("Слишком много попыток подтверждения почты с этого IP. Попробуйте позже.");

        ArgumentCaptor<AuthAttempt> captor = ArgumentCaptor.forClass(AuthAttempt.class);
        verify(authAttemptService).save(captor.capture());

        AuthAttempt saved = captor.getValue();
        assertThat(saved.getFlow()).isEqualTo(AuthAttemptFlow.VERIFY_EMAIL);
        assertThat(saved.getDecision()).isEqualTo(AuthAttemptDecision.BLOCKED);
        assertThat(saved.getReasonCode()).isEqualTo(AuthAttemptReasonCode.IP_RATE_LIMIT);
    }
}
