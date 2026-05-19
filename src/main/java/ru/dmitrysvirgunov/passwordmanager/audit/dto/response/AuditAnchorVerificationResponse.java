package ru.dmitrysvirgunov.passwordmanager.audit.dto.response;

import ru.dmitrysvirgunov.passwordmanager.audit.model.AuditScopeType;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;

public record AuditAnchorVerificationResponse(
        AuditScopeType scopeType,
        UUID scopeId,
        boolean anchorConfigured,
        boolean anchorPresent,
        Long anchoredThroughEventId,
        OffsetDateTime anchoredThroughCreatedAt,
        boolean anchorSignatureValid,
        boolean anchoredEventPresentLocally,
        boolean anchoredEventHashMatches,
        Long localHeadEventId,
        OffsetDateTime localHeadCreatedAt,
        boolean valid,
        List<String> problems
) {
}
