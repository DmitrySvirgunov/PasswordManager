package ru.dmitrysvirgunov.passwordmanager.audit.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ru.dmitrysvirgunov.passwordmanager.audit.dto.response.AuditChainVerificationResponse;
import ru.dmitrysvirgunov.passwordmanager.audit.dto.response.AuditEventResponse;
import ru.dmitrysvirgunov.passwordmanager.audit.dto.response.ListAuditEventsResponse;
import ru.dmitrysvirgunov.passwordmanager.audit.entity.AuditEvent;
import ru.dmitrysvirgunov.passwordmanager.audit.mapper.AuditResponseMapper;
import ru.dmitrysvirgunov.passwordmanager.audit.model.AuditEventVerificationResult;
import ru.dmitrysvirgunov.passwordmanager.audit.model.AuditScopeType;
import ru.dmitrysvirgunov.passwordmanager.audit.repository.AuditEventRepository;
import ru.dmitrysvirgunov.passwordmanager.auth.entity.User;
import ru.dmitrysvirgunov.passwordmanager.auth.repository.UserRepository;
import ru.dmitrysvirgunov.passwordmanager.vault.entity.VaultInvite;
import ru.dmitrysvirgunov.passwordmanager.vault.repository.VaultInviteRepository;
import tools.jackson.databind.JsonNode;

import java.util.*;
import java.time.OffsetDateTime;
import java.util.function.Function;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class AuditQueryService {

    private static final Logger log = LoggerFactory.getLogger(AuditQueryService.class);

    private final AuditEventRepository auditEventRepository;
    private final AuditResponseMapper auditResponseMapper;
    private final AuditHashService auditHashService;
    private final AuditVerificationKeyService auditVerificationKeyService;
    private final UserRepository userRepository;
    private final VaultInviteRepository vaultInviteRepository;

    @Transactional(readOnly = true)
    public ListAuditEventsResponse getVaultEvents(
            UUID vaultId,
            int page,
            int size,
            String eventType,
            String query,
            String actor,
            String affected,
            Integer lastDays,
            boolean problemsOnly
    ) {
        return getScopeEvents(AuditScopeType.VAULT, vaultId, page, size, eventType, query, actor, affected, lastDays, problemsOnly);
    }

    @Transactional(readOnly = true)
    public ListAuditEventsResponse getUserEvents(
            UUID userId,
            int page,
            int size,
            String eventType,
            String query,
            String actor,
            String affected,
            Integer lastDays,
            boolean problemsOnly
    ) {
        return getScopeEvents(AuditScopeType.USER, userId, page, size, eventType, query, actor, affected, lastDays, problemsOnly);
    }

    @Transactional(readOnly = true)
    public AuditChainVerificationResponse verifyVaultChain(UUID vaultId) {
        return verifyScopeChain(AuditScopeType.VAULT, vaultId);
    }

    @Transactional(readOnly = true)
    public AuditChainVerificationResponse verifyUserChain(UUID userId) {
        return verifyScopeChain(AuditScopeType.USER, userId);
    }

    private ListAuditEventsResponse getScopeEvents(
            AuditScopeType scopeType,
            UUID scopeId,
            int page,
            int size,
            String eventType,
            String query,
            String actor,
            String affected,
            Integer lastDays,
            boolean problemsOnly
    ) {
        if (problemsOnly) {
            return getScopeEventsInMemory(scopeType, scopeId, page, size, eventType, query, actor, affected, lastDays, true);
        }

        boolean hasParticipantFilters = (actor != null && !actor.isBlank())
                || (affected != null && !affected.isBlank());
        if (hasParticipantFilters) {
            return getScopeEventsInMemory(scopeType, scopeId, page, size, eventType, query, actor, affected, lastDays, false);
        }

        boolean hasServerSearch = query != null && !query.isBlank();

        if (!hasServerSearch) {
            return getScopeEventsPageFromRepository(scopeType, scopeId, page, size, eventType, lastDays);
        }

        return getScopeEventsSearchPageFromRepository(scopeType, scopeId, page, size, eventType, query, actor, affected, lastDays);
    }

    private ListAuditEventsResponse getScopeEventsPageFromRepository(
            AuditScopeType scopeType,
            UUID scopeId,
            int page,
            int size,
            String eventType,
            Integer lastDays
    ) {
        int normalizedSize = Math.max(1, Math.min(size, 100));
        OffsetDateTime createdAfter = resolveCreatedAfter(lastDays);

        Page<AuditEvent> eventsPage = auditEventRepository.findPageByScopeFilters(
                scopeType,
                scopeId,
                normalizeOptionalText(eventType),
                createdAfter,
                PageRequest.of(Math.max(0, page - 1), normalizedSize)
        );

        if (eventsPage.getTotalPages() > 0 && page > eventsPage.getTotalPages()) {
            eventsPage = auditEventRepository.findPageByScopeFilters(
                    scopeType,
                    scopeId,
                    normalizeOptionalText(eventType),
                    createdAfter,
                    PageRequest.of(eventsPage.getTotalPages() - 1, normalizedSize)
            );
        }

        List<AuditEvent> pageEvents = eventsPage.getContent();
        AuditDisplayLookups displayLookups = loadAuditDisplayLookups(pageEvents);
        List<AuditEventResponse> pageItems = pageEvents.stream()
                .map(event -> auditResponseMapper.toResponse(
                        event,
                        displayLookups.emailForUser(event.getActorUserId()),
                        displayLookups.targetUserEmail(event),
                        displayLookups.inviteeEmail(event)
                ))
                .toList();
        Map<Long, AuditEventVerificationResult> verificationByEventId = verifyScopeEventsById(scopeType, scopeId);
        List<AuditEventVerificationResult> pageVerifications = pageEvents.stream()
                .map(event -> verificationByEventId.get(event.getEventId()))
                .filter(Objects::nonNull)
                .toList();
        List<String> availableEventTypes = loadAvailableEventTypes(scopeType, scopeId, createdAfter, pageEvents);

        return new ListAuditEventsResponse(
                scopeType,
                scopeId,
                eventsPage.getNumber() + 1,
                normalizedSize,
                eventsPage.getTotalElements(),
                eventsPage.getTotalPages(),
                availableEventTypes,
                pageVerifications,
                pageItems
        );
    }

    private ListAuditEventsResponse getScopeEventsSearchPageFromRepository(
            AuditScopeType scopeType,
            UUID scopeId,
            int page,
            int size,
            String eventType,
            String query,
            String actor,
            String affected,
            Integer lastDays
    ) {
        int normalizedSize = Math.max(1, Math.min(size, 100));
        OffsetDateTime createdAfter = resolveCreatedAfter(lastDays);
        String normalizedQuery = likePattern(query);
        String actorPattern = likePattern(actor);
        String affectedPattern = likePattern(affected);

        Page<AuditEvent> eventsPage = auditEventRepository.searchPageByScopeFilters(
                scopeType.name(),
                scopeId,
                normalizeOptionalText(eventType),
                createdAfter,
                actorPattern,
                affectedPattern,
                normalizedQuery,
                PageRequest.of(Math.max(0, page - 1), normalizedSize)
        );

        if (eventsPage.getTotalPages() > 0 && page > eventsPage.getTotalPages()) {
            eventsPage = auditEventRepository.searchPageByScopeFilters(
                    scopeType.name(),
                    scopeId,
                    normalizeOptionalText(eventType),
                    createdAfter,
                    actorPattern,
                    affectedPattern,
                    normalizedQuery,
                    PageRequest.of(eventsPage.getTotalPages() - 1, normalizedSize)
            );
        }

        List<AuditEvent> pageEvents = eventsPage.getContent();
        AuditDisplayLookups displayLookups = loadAuditDisplayLookups(pageEvents);
        List<AuditEventResponse> pageItems = pageEvents.stream()
                .map(event -> auditResponseMapper.toResponse(
                        event,
                        displayLookups.emailForUser(event.getActorUserId()),
                        displayLookups.targetUserEmail(event),
                        displayLookups.inviteeEmail(event)
                ))
                .toList();
        Map<Long, AuditEventVerificationResult> verificationByEventId = verifyScopeEventsById(scopeType, scopeId);
        List<AuditEventVerificationResult> pageVerifications = pageEvents.stream()
                .map(event -> verificationByEventId.get(event.getEventId()))
                .filter(Objects::nonNull)
                .toList();
        List<String> availableEventTypes = loadAvailableEventTypes(scopeType, scopeId, createdAfter, pageEvents);

        return new ListAuditEventsResponse(
                scopeType,
                scopeId,
                eventsPage.getNumber() + 1,
                normalizedSize,
                eventsPage.getTotalElements(),
                eventsPage.getTotalPages(),
                availableEventTypes,
                pageVerifications,
                pageItems
        );
    }

    private ListAuditEventsResponse getScopeEventsInMemory(
            AuditScopeType scopeType,
            UUID scopeId,
            int page,
            int size,
            String eventType,
            String query,
            String actor,
            String affected,
            Integer lastDays,
            boolean problemsOnly
    ) {
        List<AuditEvent> events = loadScopeEvents(scopeType, scopeId);
        List<AuditEventVerificationResult> allVerifications = verifyEventsInMemory(events);
        Map<Long, AuditEventVerificationResult> verificationByEventId = allVerifications.stream().collect(Collectors.toMap(
                AuditEventVerificationResult::eventId,
                Function.identity()
        ));
        List<AuditEvent> candidateEvents = events.stream()
                .filter(event -> matchesDateRange(event, lastDays))
                .filter(event -> matchesEventType(event, eventType))
                .filter(event -> !problemsOnly || isProblemEvent(event, verificationByEventId))
                .toList();

        List<AuditEvent> filteredEvents;
        boolean hasResponseFilters = (query != null && !query.isBlank())
                || (actor != null && !actor.isBlank())
                || (affected != null && !affected.isBlank());

        if (!hasResponseFilters) {
            filteredEvents = candidateEvents.stream()
                    .sorted(Comparator.comparing(AuditEvent::getEventId).reversed())
                    .toList();
        } else {
            AuditDisplayLookups queryLookups = loadAuditDisplayLookups(candidateEvents);
            Map<Long, AuditEvent> candidateEventsById = candidateEvents.stream()
                    .collect(Collectors.toMap(AuditEvent::getEventId, Function.identity()));
            filteredEvents = candidateEvents.stream()
                    .map(event -> auditResponseMapper.toResponse(
                            event,
                            queryLookups.emailForUser(event.getActorUserId()),
                            queryLookups.targetUserEmail(event),
                            queryLookups.inviteeEmail(event)
                    ))
                    .filter(event -> matchesActorQuery(event, actor))
                    .filter(event -> matchesAffectedQuery(event, affected))
                    .filter(event -> matchesSearchQuery(event, query))
                    .map(event -> candidateEventsById.get(event.eventId()))
                    .sorted(Comparator.comparing(AuditEvent::getEventId).reversed())
                    .toList();
        }

        int normalizedSize = Math.max(1, Math.min(size, 100));
        long totalItems = filteredEvents.size();
        int totalPages = Math.max(1, (int) Math.ceil((double) totalItems / normalizedSize));
        int normalizedPage = Math.max(1, Math.min(page, totalPages));
        int fromIndex = totalItems == 0 ? 0 : (normalizedPage - 1) * normalizedSize;
        int toIndex = Math.min(fromIndex + normalizedSize, filteredEvents.size());
        List<AuditEvent> pageSourceEvents = filteredEvents.subList(fromIndex, toIndex);
        AuditDisplayLookups displayLookups = loadAuditDisplayLookups(pageSourceEvents);
        List<AuditEventResponse> pageItems = pageSourceEvents.stream()
                .map(event -> auditResponseMapper.toResponse(
                        event,
                        displayLookups.emailForUser(event.getActorUserId()),
                        displayLookups.targetUserEmail(event),
                        displayLookups.inviteeEmail(event)
                ))
                .toList();
        Set<Long> pageEventIds = pageSourceEvents.stream()
                .map(AuditEvent::getEventId)
                .collect(Collectors.toSet());
        List<AuditEventVerificationResult> pageVerifications = allVerifications.stream()
                .filter(result -> pageEventIds.contains(result.eventId()))
                .toList();
        List<String> availableEventTypes = candidateEvents.stream()
                .map(AuditEvent::getEventType)
                .distinct()
                .sorted()
                .toList();

        return new ListAuditEventsResponse(
                scopeType,
                scopeId,
                normalizedPage,
                normalizedSize,
                totalItems,
                totalPages,
                availableEventTypes,
                pageVerifications,
                pageItems
        );
    }

    private AuditChainVerificationResponse verifyScopeChain(AuditScopeType scopeType, UUID scopeId) {
        List<AuditEvent> events = loadScopeEvents(scopeType, scopeId);

        List<AuditEventVerificationResult> items = verifyEventsInMemory(events);
        boolean valid = items.stream().allMatch(AuditEventVerificationResult::valid);

        return new AuditChainVerificationResponse(
                scopeType,
                scopeId,
                items.size(),
                valid,
                items
        );
    }

    private List<AuditEvent> loadScopeEvents(AuditScopeType scopeType, UUID scopeId) {
        Objects.requireNonNull(scopeType, "scopeType must not be null");
        Objects.requireNonNull(scopeId, "scopeId must not be null");

        return auditEventRepository.findByScopeTypeAndScopeIdOrderByEventIdAsc(scopeType, scopeId);
    }

    private OffsetDateTime resolveCreatedAfter(Integer lastDays) {
        if (lastDays == null || lastDays <= 0) {
            return null;
        }

        return OffsetDateTime.now().minusDays(lastDays);
    }

    private String normalizeOptionalText(String value) {
        return value == null || value.isBlank() ? null : value;
    }

    private String likePattern(String value) {
        String normalized = normalizeOptionalText(value);
        return normalized == null ? null : "%" + normalized.toLowerCase(Locale.ROOT) + "%";
    }

    private List<String> loadAvailableEventTypes(
            AuditScopeType scopeType,
            UUID scopeId,
            OffsetDateTime createdAfter,
            List<AuditEvent> pageEvents
    ) {
        try {
            return auditEventRepository.findDistinctEventTypesByScopeFilters(
                    scopeType.name(),
                    scopeId,
                    createdAfter
            );
        } catch (RuntimeException exception) {
            log.warn(
                    "Failed to load distinct audit event types for scope {}:{}; falling back to current page only: {}",
                    scopeType,
                    scopeId,
                    exception.getMessage()
            );
            return pageEvents.stream()
                    .map(AuditEvent::getEventType)
                    .distinct()
                    .sorted()
                    .toList();
        }
    }

    private boolean matchesEventType(AuditEvent event, String eventType) {
        return eventType == null || eventType.isBlank() || event.getEventType().equals(eventType);
    }

    private boolean matchesDateRange(AuditEvent event, Integer lastDays) {
        if (lastDays == null || lastDays <= 0) {
            return true;
        }

        OffsetDateTime threshold = OffsetDateTime.now().minusDays(lastDays);
        return !event.getCreatedAt().isBefore(threshold);
    }

    private boolean isProblemEvent(
            AuditEvent event,
            Map<Long, AuditEventVerificationResult> verificationByEventId
    ) {
        AuditEventVerificationResult verification = verificationByEventId.get(event.getEventId());
        return verification != null && !verification.valid();
    }

    private boolean matchesSearchQuery(AuditEventResponse event, String query) {
        if (query == null || query.isBlank()) {
            return true;
        }

        String normalizedQuery = query.toLowerCase(Locale.ROOT).trim();
        String haystack = String.join(" ",
                nullSafe(event.actorEmail()),
                nullSafe(event.targetUserEmail()),
                nullSafe(event.inviteeEmail()),
                nullSafe(event.eventType()),
                searchKeywordsForEventType(event.eventType()),
                event.scopeType().name(),
                event.scopeId().toString(),
                event.meta() == null ? "" : event.meta().toString()
        ).toLowerCase(Locale.ROOT);

        return haystack.contains(normalizedQuery);
    }

    private boolean matchesActorQuery(AuditEventResponse event, String actor) {
        if (actor == null || actor.isBlank()) {
            return true;
        }

        String normalizedActor = actor.toLowerCase(Locale.ROOT).trim();

        return nullSafe(event.actorEmail())
                .toLowerCase(Locale.ROOT)
                .contains(normalizedActor);
    }

    private boolean matchesAffectedQuery(AuditEventResponse event, String affected) {
        if (affected == null || affected.isBlank()) {
            return true;
        }

        String normalizedAffected = affected.toLowerCase(Locale.ROOT).trim();

        return String.join(" ",
                        nullSafe(event.targetUserEmail()),
                        nullSafe(event.inviteeEmail()),
                        nullSafe(metaText(event.meta(), "inviteeEmail"))
                )
                .toLowerCase(Locale.ROOT)
                .contains(normalizedAffected);
    }

    private String searchKeywordsForEventType(String eventType) {
        return switch (eventType) {
            case "AUTH.USER_REGISTERED" -> "аккаунт регистрация";
            case "AUTH.LOGIN_SUCCEEDED" -> "вход сессия";
            case "AUTH.REFRESH_SUCCEEDED" -> "обновление сессия токен";
            case "AUTH.LOGOUT_SUCCEEDED" -> "выход сессия";
            case "AUTH.PASSWORD_CHANGED" -> "пароль мастер-пароль";
            case "AUTH.KEYS_ROTATED" -> "ключи аккаунт перевыпуск";
            case "AUTH.ACCOUNT_DELETED" -> "удаление аккаунт";
            case "VAULT.CREATED" -> "сейф создание";
            case "VAULT.KEY_ROTATED" -> "сейф ключ ротация";
            case "VAULT.OBJECT_CREATED" -> "запись создание";
            case "VAULT.OBJECT_UPDATED" -> "запись обновление";
            case "VAULT.OBJECT_DELETED" -> "запись удаление";
            case "VAULT.INVITE_CREATED" -> "приглашение доступ";
            case "VAULT.INVITE_REVOKED" -> "приглашение отзыв";
            case "VAULT.INVITE_ACCEPTED" -> "приглашение принято доступ";
            case "VAULT.INVITE_DECLINED" -> "приглашение отклонено";
            case "VAULT.MEMBER_ROLE_CHANGED" -> "роль участник доступ";
            case "VAULT.OWNERSHIP_TRANSFERRED" -> "владелец передача сейф";
            case "VAULT.DELETED" -> "сейф удаление";
            case "VAULT.MEMBER_REVOKED" -> "доступ отозван";
            case "RECORD_KEY_ROTATED" -> "запись ключ ротация";
            default -> "";
        };
    }

    private String nullSafe(String value) {
        return value == null ? "" : value;
    }

    private String metaText(JsonNode meta, String key) {
        if (meta == null || !meta.isObject()) {
            return null;
        }

        JsonNode value = meta.get(key);

        if (value == null || !value.isTextual()) {
            return null;
        }

        String text = value.asText();
        return text == null || text.isBlank() ? null : text;
    }

    private Map<Long, AuditEventVerificationResult> verifyScopeEventsById(
            AuditScopeType scopeType,
            UUID scopeId
    ) {
        return verifyEventsInMemory(loadScopeEvents(scopeType, scopeId)).stream()
                .collect(Collectors.toMap(
                        AuditEventVerificationResult::eventId,
                        Function.identity()
                ));
    }

    private AuditDisplayLookups loadAuditDisplayLookups(List<AuditEvent> events) {
        Set<UUID> userIds = new HashSet<>();
        Set<UUID> inviteIds = new HashSet<>();

        for (AuditEvent event : events) {
            addIfPresent(userIds, event.getActorUserId());
            addIfPresent(userIds, metaUuid(event, "userId"));
            addIfPresent(userIds, metaUuid(event, "targetUserId"));
            addIfPresent(userIds, metaUuid(event, "inviteeUserId"));
            addIfPresent(inviteIds, metaUuid(event, "inviteId"));
        }

        Map<UUID, VaultInvite> invitesById = vaultInviteRepository.findAllById(inviteIds).stream()
                .collect(Collectors.toMap(
                        VaultInvite::getInviteId,
                        Function.identity()
                ));

        for (VaultInvite invite : invitesById.values()) {
            addIfPresent(userIds, invite.getCreatedByUserId());
            addIfPresent(userIds, invite.getInviteeUserId());
        }

        Map<UUID, String> emailsByUserId = userRepository.findAllById(userIds).stream()
                .collect(Collectors.toMap(
                        User::getUserId,
                        User::getEmail
                ));

        return new AuditDisplayLookups(emailsByUserId, invitesById);
    }

    private void addIfPresent(Set<UUID> values, UUID value) {
        if (value != null) {
            values.add(value);
        }
    }

    private UUID metaUuid(AuditEvent event, String key) {
        String value = metaText(event, key);

        if (value == null) {
            return null;
        }

        try {
            return UUID.fromString(value);
        } catch (IllegalArgumentException ignored) {
            return null;
        }
    }

    private String metaText(AuditEvent event, String key) {
        JsonNode meta = event.getMeta();

        if (meta == null || !meta.isObject()) {
            return null;
        }

        JsonNode value = meta.get(key);

        if (value == null || !value.isTextual()) {
            return null;
        }

        String text = value.asText();
        return text == null || text.isBlank() ? null : text;
    }

    private record AuditDisplayLookups(
            Map<UUID, String> emailsByUserId,
            Map<UUID, VaultInvite> invitesById
    ) {

        String emailForUser(UUID userId) {
            return userId == null ? null : emailsByUserId.get(userId);
        }

        String targetUserEmail(AuditEvent event) {
            UUID targetUserId = firstNonNull(
                    metaUuid(event, "targetUserId"),
                    metaUuid(event, "inviteeUserId"),
                    metaUuid(event, "userId")
            );

            if (targetUserId != null) {
                return emailForUser(targetUserId);
            }

            VaultInvite invite = inviteForEvent(event);
            return invite != null ? invite.getInviteeEmail() : null;
        }

        String inviteeEmail(AuditEvent event) {
            String metaInviteeEmail = metaText(event, "inviteeEmail");

            if (metaInviteeEmail != null) {
                return metaInviteeEmail;
            }

            VaultInvite invite = inviteForEvent(event);
            return invite != null ? invite.getInviteeEmail() : targetUserEmail(event);
        }

        private VaultInvite inviteForEvent(AuditEvent event) {
            UUID inviteId = metaUuid(event, "inviteId");
            return inviteId == null ? null : invitesById.get(inviteId);
        }

        private UUID metaUuid(AuditEvent event, String key) {
            JsonNode meta = event.getMeta();

            if (meta == null || !meta.isObject()) {
                return null;
            }

            JsonNode value = meta.get(key);

            if (value == null || !value.isTextual()) {
                return null;
            }

            try {
                return UUID.fromString(value.asText());
            } catch (IllegalArgumentException ignored) {
                return null;
            }
        }

        private String metaText(AuditEvent event, String key) {
            JsonNode meta = event.getMeta();

            if (meta == null || !meta.isObject()) {
                return null;
            }

            JsonNode value = meta.get(key);

            if (value == null || !value.isTextual()) {
                return null;
            }

            String text = value.asText();
            return text == null || text.isBlank() ? null : text;
        }

        @SafeVarargs
        private static <T> T firstNonNull(T... values) {
            for (T value : values) {
                if (value != null) {
                    return value;
                }
            }

            return null;
        }
    }

    private List<AuditEventVerificationResult> verifyEventsInMemory(List<AuditEvent> events) {
        List<AuditEventVerificationResult> results = new ArrayList<>();
        byte[] expectedPrevHash = null;
        boolean chainValidSoFar = true;

        for (AuditEvent event : events) {
            boolean prevLinkValid = Arrays.equals(event.getPrevEventHash(), expectedPrevHash);

            byte[] recomputedHash = auditHashService.computeEventHash(
                    event.getActorUserId(),
                    event.getScopeType(),
                    event.getScopeId(),
                    event.getEventType(),
                    event.getMeta(),
                    event.getCreatedAt(),
                    expectedPrevHash
            );

            boolean hashValid = Arrays.equals(event.getEventHash(), recomputedHash);

            boolean signatureValid = auditVerificationKeyService.verify(
                    event.getSignatureKeyId(),
                    event.getEventHash(),
                    event.getEventSignature()
            );

            boolean localValid = prevLinkValid && hashValid && signatureValid;
            boolean chainValid = chainValidSoFar && localValid;

            results.add(new AuditEventVerificationResult(
                    event.getEventId(),
                    event.getScopeType(),
                    event.getScopeId(),
                    event.getEventType(),
                    chainValid,
                    prevLinkValid,
                    hashValid,
                    signatureValid,
                    chainValid
            ));

            expectedPrevHash = event.getEventHash();
            chainValidSoFar = chainValid;
        }

        return results;
    }
}
