package ru.dmitrysvirgunov.passwordmanager.audit.service;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import ru.dmitrysvirgunov.passwordmanager.audit.model.AuditScopeType;
import tools.jackson.databind.JsonNode;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.OffsetDateTime;
import java.util.UUID;

@Component
@RequiredArgsConstructor
public class AuditHashService {

    private final AuditCanonicalJsonService auditCanonicalJsonService;

    public byte[] computeEventHash(
            UUID actorUserId,
            AuditScopeType scopeType,
            UUID scopeId,
            String eventType,
            JsonNode meta,
            OffsetDateTime createdAt,
            byte[] prevEventHash
    ) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");

            if (actorUserId != null) {
                digest.update(actorUserId.toString().getBytes(StandardCharsets.UTF_8));
            }
            digest.update((byte) 0);

            digest.update(scopeType.name().getBytes(StandardCharsets.UTF_8));
            digest.update((byte) 0);

            digest.update(scopeId.toString().getBytes(StandardCharsets.UTF_8));
            digest.update((byte) 0);

            digest.update(eventType.getBytes(StandardCharsets.UTF_8));
            digest.update((byte) 0);

            String canonicalCreatedAt = createdAt.toInstant().toString();
            digest.update(canonicalCreatedAt.getBytes(StandardCharsets.UTF_8));
            digest.update((byte) 0);

            if (prevEventHash != null) {
                digest.update(prevEventHash);
            }
            digest.update((byte) 0);

            digest.update(auditCanonicalJsonService.toCanonicalBytes(meta));

            return digest.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 algorithm is not available", e);
        }
    }
}