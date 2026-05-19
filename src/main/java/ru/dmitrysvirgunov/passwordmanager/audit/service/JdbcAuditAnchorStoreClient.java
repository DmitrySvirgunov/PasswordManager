package ru.dmitrysvirgunov.passwordmanager.audit.service;

import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.jdbc.DataSourceBuilder;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import ru.dmitrysvirgunov.passwordmanager.audit.config.AuditAnchorStoreProperties;
import ru.dmitrysvirgunov.passwordmanager.audit.model.AuditAnchorEnvelope;
import ru.dmitrysvirgunov.passwordmanager.audit.model.AuditScopeType;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import javax.sql.DataSource;
import java.sql.ResultSet;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Component
@ConditionalOnProperty(prefix = "app.audit.anchor-store", name = "enabled", havingValue = "true")
@RequiredArgsConstructor
public class JdbcAuditAnchorStoreClient implements AuditAnchorStoreClient {

    private final AuditAnchorStoreProperties properties;
    private final ObjectMapper objectMapper;

    private JdbcTemplate jdbcTemplate;

    @PostConstruct
    void init() {
        if (properties.getUrl() == null || properties.getUrl().isBlank()) {
            throw new IllegalStateException("Audit anchor store URL is not configured");
        }
        if (properties.getSourceInstanceId() == null || properties.getSourceInstanceId().isBlank()) {
            throw new IllegalStateException("Audit anchor sourceInstanceId is not configured");
        }

        DataSource dataSource = DataSourceBuilder.create()
                .driverClassName(properties.getDriverClassName())
                .url(properties.getUrl())
                .username(properties.getUsername())
                .password(properties.getPassword())
                .build();

        this.jdbcTemplate = new JdbcTemplate(dataSource);

        if (properties.isAutoInitSchema()) {
            initializeSchema();
        }
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
    public void store(AuditAnchorEnvelope anchor) {
        jdbcTemplate.update(connection -> {
            var ps = connection.prepareStatement("""
                    insert into audit_anchors (
                        source_instance_id,
                        scope_type,
                        scope_id,
                        event_id,
                        event_hash,
                        event_created_at,
                        anchored_at,
                        anchor_payload,
                        anchor_key_id,
                        anchor_signature
                    ) values (?, ?, ?, ?, ?, ?, ?, cast(? as jsonb), ?, ?)
                    on conflict (source_instance_id, scope_type, scope_id, event_id) do nothing
                    """);

            ps.setString(1, anchor.sourceInstanceId());
            ps.setString(2, anchor.scopeType().name());
            ps.setObject(3, anchor.scopeId());
            ps.setLong(4, anchor.eventId());
            ps.setBytes(5, anchor.eventHash());
            ps.setObject(6, anchor.eventCreatedAt());
            ps.setObject(7, anchor.anchoredAt());
            ps.setString(8, anchor.anchorPayload().toString());
            ps.setString(9, anchor.anchorKeyId());
            ps.setBytes(10, anchor.anchorSignature());

            return ps;
        });
    }

    @Override
    public Optional<AuditAnchorEnvelope> findLatestAnchor(AuditScopeType scopeType, UUID scopeId) {
        List<AuditAnchorEnvelope> rows = jdbcTemplate.query("""
                        select source_instance_id,
                               scope_type,
                               scope_id,
                               event_id,
                               event_hash,
                               event_created_at,
                               anchored_at,
                               anchor_payload,
                               anchor_key_id,
                               anchor_signature
                        from audit_anchors
                        where source_instance_id = ?
                          and scope_type = ?
                          and scope_id = ?
                        order by event_id desc
                        limit 1
                        """,
                (rs, rowNum) -> mapAnchor(rs),
                properties.getSourceInstanceId(),
                scopeType.name(),
                scopeId
        );

        return rows.stream().findFirst();
    }

    private AuditAnchorEnvelope mapAnchor(ResultSet rs) throws java.sql.SQLException {
        try {
            JsonNode payload = objectMapper.readTree(rs.getString("anchor_payload"));
            return new AuditAnchorEnvelope(
                    rs.getString("source_instance_id"),
                    AuditScopeType.valueOf(rs.getString("scope_type")),
                    rs.getObject("scope_id", UUID.class),
                    rs.getLong("event_id"),
                    rs.getBytes("event_hash"),
                    rs.getObject("event_created_at", OffsetDateTime.class),
                    rs.getObject("anchored_at", OffsetDateTime.class),
                    payload,
                    rs.getString("anchor_key_id"),
                    rs.getBytes("anchor_signature")
            );
        } catch (Exception exception) {
            throw new IllegalStateException("Failed to read audit anchor from external store", exception);
        }
    }

    private void initializeSchema() {
        jdbcTemplate.execute("""
                create table if not exists audit_anchors (
                    anchor_id bigserial primary key,
                    source_instance_id text not null,
                    scope_type text not null,
                    scope_id uuid not null,
                    event_id bigint not null,
                    event_hash bytea not null,
                    event_created_at timestamptz not null,
                    anchored_at timestamptz not null,
                    anchor_payload jsonb not null,
                    anchor_key_id text not null,
                    anchor_signature bytea not null,
                    created_at timestamptz not null default now(),
                    constraint uq_audit_anchors_scope_event
                        unique (source_instance_id, scope_type, scope_id, event_id),
                    constraint chk_audit_anchors_scope_type
                        check (scope_type in ('VAULT', 'USER'))
                )
                """);
        jdbcTemplate.execute("""
                create index if not exists ix_audit_anchors_scope_event
                    on audit_anchors (source_instance_id, scope_type, scope_id, event_id desc)
                """);
    }
}
