package ru.dmitrysvirgunov.passwordmanager.audit.dto.response;

import ru.dmitrysvirgunov.passwordmanager.audit.model.AuditEventVerificationResult;
import ru.dmitrysvirgunov.passwordmanager.audit.model.AuditScopeType;

import java.util.List;
import java.util.UUID;

public record ListAuditEventsResponse(
        AuditScopeType scopeType,
        UUID scopeId,
        int page,
        int size,
        long totalItems,
        int totalPages,
        List<String> availableEventTypes,
        List<AuditEventVerificationResult> itemVerifications,
        List<AuditEventResponse> items
) {
}
