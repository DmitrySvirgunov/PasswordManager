package ru.dmitrysvirgunov.passwordmanager.audit.dto.response;

import ru.dmitrysvirgunov.passwordmanager.audit.model.AuditScopeType;
import tools.jackson.databind.JsonNode;

import java.time.OffsetDateTime;
import java.util.UUID;

public record AuditEventResponse(
        Long eventId,
        UUID actorUserId,
        String actorEmail,
        AuditScopeType scopeType,
        UUID scopeId,
        String eventType,
        JsonNode meta,
        String targetUserEmail,
        String inviteeEmail,
        String eventHashBase64,
        String prevEventHashBase64,
        String signatureKeyId,
        String eventSignatureBase64,
        OffsetDateTime createdAt
) {
}
