package ru.dmitrysvirgunov.passwordmanager.audit.model;

import tools.jackson.databind.JsonNode;

import java.time.OffsetDateTime;
import java.util.UUID;

public record AuditAnchorEnvelope(
        String sourceInstanceId,
        AuditScopeType scopeType,
        UUID scopeId,
        Long eventId,
        byte[] eventHash,
        OffsetDateTime eventCreatedAt,
        OffsetDateTime anchoredAt,
        JsonNode anchorPayload,
        String anchorKeyId,
        byte[] anchorSignature
) {
}
