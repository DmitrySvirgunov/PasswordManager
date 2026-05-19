package ru.dmitrysvirgunov.passwordmanager.audit.service;

import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.ConnectionCallback;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import ru.dmitrysvirgunov.passwordmanager.audit.model.AuditScopeType;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuditScopeLockService {

    private final JdbcTemplate jdbcTemplate;

    public void lock(AuditScopeType scopeType, UUID scopeId) {
        long lockKey = toLockKey(scopeType, scopeId);

        jdbcTemplate.execute((ConnectionCallback<Object>) connection -> {
            try (var ps = connection.prepareStatement("select pg_advisory_xact_lock(?)")) {
                ps.setLong(1, lockKey);
                ps.execute();
            }
            return null;
        });
    }

    private long toLockKey(AuditScopeType scopeType, UUID scopeId) {
        try {
            String raw = scopeType.name() + ":" + scopeId;
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(raw.getBytes(StandardCharsets.UTF_8));
            return ByteBuffer.wrap(digest, 0, Long.BYTES).getLong();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to compute audit scope lock key", e);
        }
    }
}