package ru.dmitrysvirgunov.passwordmanager.audit.model;

import java.util.UUID;

public record AuditEventVerificationResult(
        Long eventId,
        AuditScopeType scopeType,
        UUID scopeId,
        String eventType,
        boolean chainValid,
        boolean prevLinkValid,
        boolean hashValid,
        boolean signatureValid,
        boolean valid
) {
}
