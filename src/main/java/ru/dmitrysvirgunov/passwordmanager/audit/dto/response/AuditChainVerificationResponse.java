package ru.dmitrysvirgunov.passwordmanager.audit.dto.response;

import ru.dmitrysvirgunov.passwordmanager.audit.model.AuditScopeType;
import ru.dmitrysvirgunov.passwordmanager.audit.model.AuditEventVerificationResult;

import java.util.List;
import java.util.UUID;

public record AuditChainVerificationResponse(
        AuditScopeType scopeType,
        UUID scopeId,
        int totalEvents,
        boolean valid,
        List<AuditEventVerificationResult> items
) {
}