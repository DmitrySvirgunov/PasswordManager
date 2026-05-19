package ru.dmitrysvirgunov.passwordmanager.audit.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import ru.dmitrysvirgunov.passwordmanager.audit.dto.response.AuditEventResponse;
import ru.dmitrysvirgunov.passwordmanager.audit.dto.response.ListAuditEventsResponse;
import ru.dmitrysvirgunov.passwordmanager.audit.entity.AuditEvent;
import ru.dmitrysvirgunov.passwordmanager.audit.mapper.AuditResponseMapper;
import ru.dmitrysvirgunov.passwordmanager.audit.model.AuditScopeType;
import ru.dmitrysvirgunov.passwordmanager.audit.repository.AuditEventRepository;
import ru.dmitrysvirgunov.passwordmanager.auth.entity.User;
import ru.dmitrysvirgunov.passwordmanager.auth.model.UserStatus;
import ru.dmitrysvirgunov.passwordmanager.auth.repository.UserRepository;
import ru.dmitrysvirgunov.passwordmanager.vault.repository.VaultInviteRepository;
import tools.jackson.databind.node.JsonNodeFactory;
import tools.jackson.databind.node.ObjectNode;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@DisplayName("Проверка выборки и верификации аудита")
class AuditQueryServiceTest {

    @Mock
    private AuditEventRepository auditEventRepository;

    @Spy
    private AuditResponseMapper auditResponseMapper = new AuditResponseMapper();

    @Mock
    private AuditHashService auditHashService;

    @Mock
    private AuditVerificationKeyService auditVerificationKeyService;

    @Mock
    private UserRepository userRepository;

    @Mock
    private VaultInviteRepository vaultInviteRepository;

    @InjectMocks
    private AuditQueryService auditQueryService;

    private UUID vaultId;
    private UUID aliceId;
    private UUID bobId;
    private UUID charlieId;
    private AuditEvent eventByAlice;
    private AuditEvent eventByCharlieForBob;

    @BeforeEach
    void setUp() {
        vaultId = UUID.randomUUID();
        aliceId = UUID.randomUUID();
        bobId = UUID.randomUUID();
        charlieId = UUID.randomUUID();

        eventByAlice = AuditEvent.builder()
                .eventId(101L)
                .actorUserId(aliceId)
                .scopeType(AuditScopeType.VAULT)
                .scopeId(vaultId)
                .eventType("VAULT.CREATED")
                .meta(objectMeta())
                .eventHash(new byte[]{1})
                .prevEventHash(null)
                .signatureKeyId("sig-1")
                .eventSignature(new byte[]{11})
                .createdAt(OffsetDateTime.now().minusMinutes(5))
                .build();

        eventByCharlieForBob = AuditEvent.builder()
                .eventId(102L)
                .actorUserId(charlieId)
                .scopeType(AuditScopeType.VAULT)
                .scopeId(vaultId)
                .eventType("VAULT.MEMBER_ROLE_CHANGED")
                .meta(objectMeta().put("targetUserId", bobId.toString()))
                .eventHash(new byte[]{2})
                .prevEventHash(new byte[]{1})
                .signatureKeyId("sig-2")
                .eventSignature(new byte[]{22})
                .createdAt(OffsetDateTime.now().minusMinutes(1))
                .build();

        lenient().when(auditEventRepository.findByScopeTypeAndScopeIdOrderByEventIdAsc(AuditScopeType.VAULT, vaultId))
                .thenReturn(List.of(eventByAlice, eventByCharlieForBob));
        lenient().doReturn(List.of(
                user(aliceId, "alice@example.test"),
                user(bobId, "bob@example.test"),
                user(charlieId, "charlie@example.test")
        )).when(userRepository).findAllById(any());
        lenient().doReturn(List.of()).when(vaultInviteRepository).findAllById(any());
        lenient().when(auditHashService.computeEventHash(any(), any(), any(), anyString(), any(), any(), any()))
                .thenReturn(new byte[]{1}, new byte[]{2});
        lenient().when(auditVerificationKeyService.verify(anyString(), any(), any())).thenReturn(true);
    }

    @Test
    @DisplayName("Должен фильтровать события сейфа по почте исполнителя через разрешенный контекст отображения")
    void shouldFilterVaultEventsByActorEmailUsingResolvedDisplayContext() {
        ListAuditEventsResponse response = auditQueryService.getVaultEvents(
                vaultId,
                1,
                20,
                null,
                null,
                "charlie@example.test",
                null,
                null,
                false
        );

        assertThat(response.items())
                .extracting(event -> event.eventId())
                .containsExactly(102L);

        verify(auditEventRepository, never()).searchPageByScopeFilters(anyString(), any(), any(), any(), any(), any(), any(), any());
    }

    @Test
    @DisplayName("Должен фильтровать события сейфа по почте затронутого пользователя через разрешенный контекст отображения")
    void shouldFilterVaultEventsByAffectedUserEmailUsingResolvedDisplayContext() {
        ListAuditEventsResponse response = auditQueryService.getVaultEvents(
                vaultId,
                1,
                20,
                null,
                null,
                null,
                "bob@example.test",
                null,
                false
        );

        assertThat(response.items())
                .extracting(event -> event.eventId())
                .containsExactly(102L);

        verify(auditEventRepository, never()).searchPageByScopeFilters(anyString(), any(), any(), any(), any(), any(), any(), any());
    }

    @Test
    @DisplayName("Должен брать типы событий с текущей страницы, если отдельный запрос типов завершился ошибкой")
    void shouldFallbackToCurrentPageEventTypesWhenDistinctQueryFails() {
        UUID userId = UUID.randomUUID();
        AuditEvent registered = AuditEvent.builder()
                .eventId(1L)
                .actorUserId(userId)
                .scopeType(AuditScopeType.USER)
                .scopeId(userId)
                .eventType("AUTH.USER_REGISTERED")
                .meta(objectMeta().put("userId", userId.toString()))
                .eventHash(new byte[]{1})
                .prevEventHash(null)
                .signatureKeyId("sig-1")
                .eventSignature(new byte[]{11})
                .createdAt(OffsetDateTime.now().minusMinutes(2))
                .build();
        AuditEvent rotated = AuditEvent.builder()
                .eventId(2L)
                .actorUserId(userId)
                .scopeType(AuditScopeType.USER)
                .scopeId(userId)
                .eventType("AUTH.KEYS_ROTATED")
                .meta(objectMeta()
                        .put("userId", userId.toString())
                        .put("newEncryptionKeyVersion", 2))
                .eventHash(new byte[]{2})
                .prevEventHash(new byte[]{1})
                .signatureKeyId("sig-2")
                .eventSignature(new byte[]{22})
                .createdAt(OffsetDateTime.now().minusMinutes(1))
                .build();

        when(auditEventRepository.findPageByScopeFilters(
                eq(AuditScopeType.USER),
                eq(userId),
                eq(null),
                eq(null),
                any(PageRequest.class)
        )).thenReturn(new PageImpl<>(List.of(rotated, registered), PageRequest.of(0, 20), 2));
        when(auditEventRepository.findDistinctEventTypesByScopeFilters("USER", userId, null))
                .thenThrow(new IllegalStateException("boom"));
        when(auditEventRepository.findByScopeTypeAndScopeIdOrderByEventIdAsc(AuditScopeType.USER, userId))
                .thenReturn(List.of(registered, rotated));
        doReturn(List.of(user(userId, "user@example.test"))).when(userRepository).findAllById(any());
        when(auditHashService.computeEventHash(any(), any(), any(), anyString(), any(), any(), any()))
                .thenReturn(new byte[]{2}, new byte[]{1});
        when(auditVerificationKeyService.verify(anyString(), any(), any())).thenReturn(true);

        ListAuditEventsResponse response = auditQueryService.getUserEvents(
                userId,
                1,
                20,
                null,
                null,
                null,
                null,
                null,
                false
        );

        assertThat(response.items())
                .extracting(AuditEventResponse::eventId)
                .containsExactly(2L, 1L);
        assertThat(response.availableEventTypes())
                .containsExactly("AUTH.KEYS_ROTATED", "AUTH.USER_REGISTERED");
    }

    @Test
    @DisplayName("Должен помечать сломанными только события после разрыва цепочки")
    void shouldMarkOnlyEventsAfterChainGapAsBroken() {
        UUID userId = UUID.randomUUID();

        AuditEvent first = AuditEvent.builder()
                .eventId(257L)
                .actorUserId(userId)
                .scopeType(AuditScopeType.USER)
                .scopeId(userId)
                .eventType("AUTH.LOGIN_SUCCEEDED")
                .meta(objectMeta())
                .eventHash(new byte[]{1})
                .prevEventHash(null)
                .signatureKeyId("sig-1")
                .eventSignature(new byte[]{11})
                .createdAt(OffsetDateTime.now().minusMinutes(3))
                .build();
        AuditEvent tailAfterGap = AuditEvent.builder()
                .eventId(259L)
                .actorUserId(userId)
                .scopeType(AuditScopeType.USER)
                .scopeId(userId)
                .eventType("AUTH.LOGOUT_SUCCEEDED")
                .meta(objectMeta())
                .eventHash(new byte[]{3})
                .prevEventHash(new byte[]{2})
                .signatureKeyId("sig-1")
                .eventSignature(new byte[]{33})
                .createdAt(OffsetDateTime.now().minusMinutes(1))
                .build();
        AuditEvent laterAfterBrokenTail = AuditEvent.builder()
                .eventId(260L)
                .actorUserId(userId)
                .scopeType(AuditScopeType.USER)
                .scopeId(userId)
                .eventType("AUTH.REFRESH_SUCCEEDED")
                .meta(objectMeta())
                .eventHash(new byte[]{4})
                .prevEventHash(new byte[]{3})
                .signatureKeyId("sig-1")
                .eventSignature(new byte[]{44})
                .createdAt(OffsetDateTime.now())
                .build();

        when(auditEventRepository.findPageByScopeFilters(
                eq(AuditScopeType.USER),
                eq(userId),
                eq(null),
                eq(null),
                any(PageRequest.class)
        )).thenReturn(new PageImpl<>(List.of(laterAfterBrokenTail, tailAfterGap, first), PageRequest.of(0, 20), 3));
        when(auditEventRepository.findDistinctEventTypesByScopeFilters("USER", userId, null))
                .thenReturn(List.of("AUTH.LOGIN_SUCCEEDED", "AUTH.LOGOUT_SUCCEEDED", "AUTH.REFRESH_SUCCEEDED"));
        doReturn(List.of(user(userId, "user@example.test"))).when(userRepository).findAllById(any());
        when(auditEventRepository.findByScopeTypeAndScopeIdOrderByEventIdAsc(AuditScopeType.USER, userId))
                .thenReturn(List.of(first, tailAfterGap, laterAfterBrokenTail));
        when(auditHashService.computeEventHash(any(), any(), any(), anyString(), any(), any(), any()))
                .thenReturn(new byte[]{1}, new byte[]{9}, new byte[]{4});
        when(auditVerificationKeyService.verify(anyString(), any(), any())).thenReturn(true);

        ListAuditEventsResponse response = auditQueryService.getUserEvents(
                userId,
                1,
                20,
                null,
                null,
                null,
                null,
                null,
                false
        );

        assertThat(response.itemVerifications())
                .extracting(result -> result.eventId(), result -> result.valid())
                .containsExactly(
                        org.assertj.core.groups.Tuple.tuple(260L, false),
                        org.assertj.core.groups.Tuple.tuple(259L, false),
                        org.assertj.core.groups.Tuple.tuple(257L, true)
                );
    }

    private User user(UUID userId, String email) {
        OffsetDateTime now = OffsetDateTime.now();
        return User.builder()
                .userId(userId)
                .email(email)
                .status(UserStatus.ACTIVE)
                .emailVerifiedAt(now)
                .createdAt(now)
                .updatedAt(now)
                .build();
    }

    private ObjectNode objectMeta() {
        return JsonNodeFactory.instance.objectNode();
    }
}
