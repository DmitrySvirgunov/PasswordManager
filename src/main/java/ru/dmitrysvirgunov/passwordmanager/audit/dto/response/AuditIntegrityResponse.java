package ru.dmitrysvirgunov.passwordmanager.audit.dto.response;

import ru.dmitrysvirgunov.passwordmanager.audit.model.AuditScopeType;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;

public record AuditIntegrityResponse(
        AuditScopeType scopeType,
        UUID scopeId,
        int totalEvents,
        boolean chainValid,
        boolean anchorConfigured,
        boolean anchorValid,
        boolean valid,
        Long localHeadEventId,
        OffsetDateTime localHeadCreatedAt,
        Long anchoredThroughEventId,
        OffsetDateTime anchoredThroughCreatedAt,
        List<String> problems
) {
}
