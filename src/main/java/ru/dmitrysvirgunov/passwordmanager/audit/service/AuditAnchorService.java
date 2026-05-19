package ru.dmitrysvirgunov.passwordmanager.audit.service;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ru.dmitrysvirgunov.passwordmanager.audit.config.AuditAnchorStoreProperties;
import ru.dmitrysvirgunov.passwordmanager.audit.dto.response.AuditAnchorVerificationResponse;
import ru.dmitrysvirgunov.passwordmanager.audit.dto.response.AuditChainVerificationResponse;
import ru.dmitrysvirgunov.passwordmanager.audit.dto.response.AuditIntegrityResponse;
import ru.dmitrysvirgunov.passwordmanager.audit.entity.AuditAnchorOutbox;
import ru.dmitrysvirgunov.passwordmanager.audit.entity.AuditEvent;
import ru.dmitrysvirgunov.passwordmanager.audit.entity.AuditScopeHead;
import ru.dmitrysvirgunov.passwordmanager.audit.entity.AuditScopeHeadId;
import ru.dmitrysvirgunov.passwordmanager.audit.model.AuditAnchorEnvelope;
import ru.dmitrysvirgunov.passwordmanager.audit.model.AuditScopeType;
import ru.dmitrysvirgunov.passwordmanager.audit.repository.AuditAnchorOutboxRepository;
import ru.dmitrysvirgunov.passwordmanager.audit.repository.AuditEventRepository;
import ru.dmitrysvirgunov.passwordmanager.audit.repository.AuditScopeHeadRepository;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.JsonNodeFactory;
import tools.jackson.databind.node.ObjectNode;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuditAnchorService {

    private final AuditAnchorOutboxRepository auditAnchorOutboxRepository;
    private final AuditAnchorStoreProperties auditAnchorStoreProperties;
    private final AuditAnchorStoreClient auditAnchorStoreClient;
    private final AuditCanonicalJsonService auditCanonicalJsonService;
    private final AuditEventRepository auditEventRepository;
    private final AuditQueryService auditQueryService;
    private final AuditScopeHeadRepository auditScopeHeadRepository;
    private final AuditSigningService auditSigningService;
    private final AuditVerificationKeyService auditVerificationKeyService;

    public void enqueueAnchor(AuditEvent event) {
        AuditAnchorEnvelope anchor = buildAnchorEnvelope(event);
        OffsetDateTime now = normalizeTimestamp(OffsetDateTime.now(ZoneOffset.UTC));

        auditAnchorOutboxRepository.save(AuditAnchorOutbox.builder()
                .sourceInstanceId(anchor.sourceInstanceId())
                .scopeType(anchor.scopeType())
                .scopeId(anchor.scopeId())
                .eventId(anchor.eventId())
                .eventHash(anchor.eventHash())
                .eventCreatedAt(anchor.eventCreatedAt())
                .anchoredAt(anchor.anchoredAt())
                .anchorPayload(anchor.anchorPayload())
                .anchorKeyId(anchor.anchorKeyId())
                .anchorSignature(anchor.anchorSignature())
                .createdAt(now)
                .exportAttempts(0)
                .build());
    }

    @Transactional(readOnly = true)
    public AuditAnchorVerificationResponse verifyVaultAnchor(UUID vaultId) {
        return verifyScopeAnchor(AuditScopeType.VAULT, vaultId);
    }

    @Transactional(readOnly = true)
    public AuditAnchorVerificationResponse verifyUserAnchor(UUID userId) {
        return verifyScopeAnchor(AuditScopeType.USER, userId);
    }

    @Transactional(readOnly = true)
    public AuditIntegrityResponse getVaultIntegrity(UUID vaultId) {
        return getScopeIntegrity(AuditScopeType.VAULT, vaultId);
    }

    @Transactional(readOnly = true)
    public AuditIntegrityResponse getUserIntegrity(UUID userId) {
        return getScopeIntegrity(AuditScopeType.USER, userId);
    }

    private AuditIntegrityResponse getScopeIntegrity(AuditScopeType scopeType, UUID scopeId) {
        AuditChainVerificationResponse chain = switch (scopeType) {
            case VAULT -> auditQueryService.verifyVaultChain(scopeId);
            case USER -> auditQueryService.verifyUserChain(scopeId);
        };

        AuditAnchorVerificationResponse anchor = verifyScopeAnchor(scopeType, scopeId);

        return new AuditIntegrityResponse(
                scopeType,
                scopeId,
                chain.totalEvents(),
                chain.valid(),
                anchor.anchorConfigured(),
                anchor.valid(),
                chain.valid() && anchor.valid(),
                anchor.localHeadEventId(),
                anchor.localHeadCreatedAt(),
                anchor.anchoredThroughEventId(),
                anchor.anchoredThroughCreatedAt(),
                anchor.problems()
        );
    }

    private AuditAnchorVerificationResponse verifyScopeAnchor(AuditScopeType scopeType, UUID scopeId) {
        List<String> problems = new ArrayList<>();
        Optional<AuditScopeHead> localHead = findLocalHead(scopeType, scopeId);

        if (!auditAnchorStoreClient.isEnabled()) {
            problems.add("External audit anchor store is not configured");
            return new AuditAnchorVerificationResponse(
                    scopeType,
                    scopeId,
                    false,
                    false,
                    null,
                    null,
                    false,
                    false,
                    false,
                    localHead.map(AuditScopeHead::getHeadEventId).orElse(null),
                    localHead.map(AuditScopeHead::getHeadCreatedAt).orElse(null),
                    false,
                    List.copyOf(problems)
            );
        }

        Optional<AuditAnchorEnvelope> latestAnchor;
        try {
            latestAnchor = auditAnchorStoreClient.findLatestAnchor(scopeType, scopeId);
        } catch (RuntimeException exception) {
            problems.add("Failed to query external audit anchor store: " + safeMessage(exception));
            return new AuditAnchorVerificationResponse(
                    scopeType,
                    scopeId,
                    true,
                    false,
                    null,
                    null,
                    false,
                    false,
                    false,
                    localHead.map(AuditScopeHead::getHeadEventId).orElse(null),
                    localHead.map(AuditScopeHead::getHeadCreatedAt).orElse(null),
                    false,
                    List.copyOf(problems)
            );
        }

        if (latestAnchor.isEmpty()) {
            if (localHead.isPresent()) {
                problems.add("External anchor is missing for a non-empty local audit chain");
            }

            return new AuditAnchorVerificationResponse(
                    scopeType,
                    scopeId,
                    true,
                    false,
                    null,
                    null,
                    false,
                    false,
                    false,
                    localHead.map(AuditScopeHead::getHeadEventId).orElse(null),
                    localHead.map(AuditScopeHead::getHeadCreatedAt).orElse(null),
                    localHead.isEmpty(),
                    List.copyOf(problems)
            );
        }

        AuditAnchorEnvelope anchor = latestAnchor.get();
        boolean anchorPayloadConsistent = anchorPayloadConsistent(anchor, problems);
        boolean signatureValid = auditVerificationKeyService.verify(
                anchor.anchorKeyId(),
                auditCanonicalJsonService.toCanonicalBytes(anchor.anchorPayload()),
                anchor.anchorSignature()
        );
        if (!signatureValid) {
            problems.add("External anchor signature is invalid");
        }

        Optional<AuditEvent> anchoredEvent = auditEventRepository.findByScopeTypeAndScopeIdAndEventId(
                scopeType,
                scopeId,
                anchor.eventId()
        );

        boolean anchoredEventPresentLocally = anchoredEvent.isPresent();
        if (!anchoredEventPresentLocally) {
            problems.add("Locally anchored event is missing from audit_events");
        }

        boolean anchoredEventHashMatches = anchoredEvent
                .map(event -> Arrays.equals(event.getEventHash(), anchor.eventHash()))
                .orElse(false);
        if (anchoredEventPresentLocally && !anchoredEventHashMatches) {
            problems.add("Locally anchored event hash does not match external anchor");
        }

        if (localHead.isPresent() && localHead.get().getHeadEventId() < anchor.eventId()) {
            problems.add("Local audit head is older than the latest external anchor");
        }

        boolean valid = anchorPayloadConsistent
                && signatureValid
                && anchoredEventPresentLocally
                && anchoredEventHashMatches
                && localHead.map(head -> head.getHeadEventId() >= anchor.eventId()).orElse(false);

        if (localHead.isEmpty() && latestAnchor.isPresent()) {
            valid = false;
            problems.add("Local audit chain is empty but external anchor exists");
        }

        return new AuditAnchorVerificationResponse(
                scopeType,
                scopeId,
                true,
                true,
                anchor.eventId(),
                anchor.eventCreatedAt(),
                signatureValid,
                anchoredEventPresentLocally,
                anchoredEventHashMatches,
                localHead.map(AuditScopeHead::getHeadEventId).orElse(null),
                localHead.map(AuditScopeHead::getHeadCreatedAt).orElse(null),
                valid,
                List.copyOf(problems)
        );
    }

    private Optional<AuditScopeHead> findLocalHead(AuditScopeType scopeType, UUID scopeId) {
        return auditScopeHeadRepository.findById(new AuditScopeHeadId(scopeType, scopeId))
                .or(() -> auditEventRepository.findTopByScopeTypeAndScopeIdOrderByEventIdDesc(scopeType, scopeId)
                        .map(event -> AuditScopeHead.builder()
                                .scopeType(scopeType)
                                .scopeId(scopeId)
                                .headEventId(event.getEventId())
                                .headEventHash(event.getEventHash())
                                .headCreatedAt(event.getCreatedAt())
                                .updatedAt(event.getCreatedAt())
                                .build()));
    }

    private boolean anchorPayloadConsistent(AuditAnchorEnvelope anchor, List<String> problems) {
        JsonNode payload = anchor.anchorPayload();
        if (payload == null || !payload.isObject()) {
            problems.add("External anchor payload is missing or malformed");
            return false;
        }

        boolean consistent = true;

        consistent &= textEquals(payload, "sourceInstanceId", anchor.sourceInstanceId(), problems, "Anchor payload sourceInstanceId mismatch");
        consistent &= textEquals(payload, "scopeType", anchor.scopeType().name(), problems, "Anchor payload scopeType mismatch");
        consistent &= textEquals(payload, "scopeId", anchor.scopeId().toString(), problems, "Anchor payload scopeId mismatch");
        consistent &= numberEquals(payload, "eventId", anchor.eventId(), problems, "Anchor payload eventId mismatch");
        consistent &= textEquals(
                payload,
                "eventHashBase64",
                Base64.getEncoder().encodeToString(anchor.eventHash()),
                problems,
                "Anchor payload eventHash mismatch"
        );

        return consistent;
    }

    private boolean textEquals(
            JsonNode payload,
            String fieldName,
            String expected,
            List<String> problems,
            String message
    ) {
        JsonNode node = payload.get(fieldName);
        if (node == null || !node.isTextual() || !expected.equals(node.asText())) {
            problems.add(message);
            return false;
        }

        return true;
    }

    private boolean numberEquals(
            JsonNode payload,
            String fieldName,
            Long expected,
            List<String> problems,
            String message
    ) {
        JsonNode node = payload.get(fieldName);
        if (node == null || !node.canConvertToLong() || expected == null || expected.longValue() != node.asLong()) {
            problems.add(message);
            return false;
        }

        return true;
    }

    private AuditAnchorEnvelope buildAnchorEnvelope(AuditEvent event) {
        OffsetDateTime anchoredAt = normalizeTimestamp(OffsetDateTime.now(ZoneOffset.UTC));
        ObjectNode payload = JsonNodeFactory.instance.objectNode();
        payload.put("sourceInstanceId", auditAnchorStoreProperties.getSourceInstanceId());
        payload.put("scopeType", event.getScopeType().name());
        payload.put("scopeId", event.getScopeId().toString());
        payload.put("eventId", event.getEventId());
        payload.put("eventHashBase64", Base64.getEncoder().encodeToString(event.getEventHash()));
        payload.put("eventCreatedAt", event.getCreatedAt().toString());
        payload.put("anchoredAt", anchoredAt.toString());

        JsonNode canonicalPayload = auditCanonicalJsonService.canonicalize(payload);
        byte[] payloadSignature = auditSigningService.sign(
                auditCanonicalJsonService.toCanonicalBytes(canonicalPayload)
        );

        return new AuditAnchorEnvelope(
                auditAnchorStoreProperties.getSourceInstanceId(),
                event.getScopeType(),
                event.getScopeId(),
                event.getEventId(),
                event.getEventHash(),
                event.getCreatedAt(),
                anchoredAt,
                canonicalPayload,
                auditSigningService.keyId(),
                payloadSignature
        );
    }

    private OffsetDateTime normalizeTimestamp(OffsetDateTime value) {
        return value.withOffsetSameInstant(ZoneOffset.UTC)
                .truncatedTo(ChronoUnit.MICROS);
    }

    private String safeMessage(RuntimeException exception) {
        String message = exception.getMessage();
        return message == null || message.isBlank() ? exception.getClass().getSimpleName() : message;
    }
}
