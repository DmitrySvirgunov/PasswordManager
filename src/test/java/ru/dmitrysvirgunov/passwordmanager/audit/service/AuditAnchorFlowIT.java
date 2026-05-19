package ru.dmitrysvirgunov.passwordmanager.audit.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.jdbc.DataSourceBuilder;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import ru.dmitrysvirgunov.passwordmanager.audit.dto.response.AuditAnchorVerificationResponse;
import ru.dmitrysvirgunov.passwordmanager.audit.dto.response.AuditIntegrityResponse;
import ru.dmitrysvirgunov.passwordmanager.audit.entity.AuditAnchorOutbox;
import ru.dmitrysvirgunov.passwordmanager.audit.repository.AuditAnchorOutboxRepository;
import ru.dmitrysvirgunov.passwordmanager.support.AbstractPostgresIntegrationTest;

import javax.sql.DataSource;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.OffsetDateTime;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("Интеграционные тесты независимого подтверждения журнала")
@Testcontainers
class AuditAnchorFlowIT extends AbstractPostgresIntegrationTest {

    private static final String SOURCE_INSTANCE_ID = "it-anchor-node";
    private static final String SIGNING_KEY_ID = "audit-ed25519-it";
    private static final String PRIVATE_KEY_BASE64;
    private static final String PUBLIC_KEY_BASE64;

    @Container
    @SuppressWarnings("resource")
    private static final PostgreSQLContainer<?> EXTERNAL_AUDIT_DB =
            new PostgreSQLContainer<>("postgres:16.1");

    static {
        try {
            KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
            PRIVATE_KEY_BASE64 = Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());
            PUBLIC_KEY_BASE64 = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
        } catch (Exception exception) {
            throw new ExceptionInInitializerError(exception);
        }
    }

    @DynamicPropertySource
    static void overrideAuditProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.task.scheduling.enabled", () -> "false");
        registry.add("app.audit.signing.key-id", () -> SIGNING_KEY_ID);
        registry.add("app.audit.signing.private-key-pkcs8-base64", () -> PRIVATE_KEY_BASE64);
        registry.add("app.audit.signing.public-key-x509-base64", () -> PUBLIC_KEY_BASE64);
        registry.add("app.audit.anchor-store.enabled", () -> "true");
        registry.add("app.audit.anchor-store.source-instance-id", () -> SOURCE_INSTANCE_ID);
        registry.add("app.audit.anchor-store.url", EXTERNAL_AUDIT_DB::getJdbcUrl);
        registry.add("app.audit.anchor-store.username", EXTERNAL_AUDIT_DB::getUsername);
        registry.add("app.audit.anchor-store.password", EXTERNAL_AUDIT_DB::getPassword);
        registry.add("app.audit.anchor-store.driver-class-name", () -> "org.postgresql.Driver");
        registry.add("app.audit.anchor-store.auto-init-schema", () -> "true");
        registry.add("app.audit.anchor-store.batch-size", () -> "10");
    }

    @Autowired
    private AuditAnchorOutboxRepository auditAnchorOutboxRepository;

    @Autowired
    private AuditAnchorBackfillJob auditAnchorBackfillJob;

    @Autowired
    private AuditAnchorExportJob auditAnchorExportJob;

    @Autowired
    private AuditAnchorService auditAnchorService;

    @Autowired
    private AuditService auditService;

    @Autowired
    private JdbcClient jdbcClient;

    private JdbcTemplate externalAuditJdbcTemplate;

    @BeforeEach
    void setUp() {
        DataSource externalDataSource = DataSourceBuilder.create()
                .driverClassName("org.postgresql.Driver")
                .url(EXTERNAL_AUDIT_DB.getJdbcUrl())
                .username(EXTERNAL_AUDIT_DB.getUsername())
                .password(EXTERNAL_AUDIT_DB.getPassword())
                .build();
        externalAuditJdbcTemplate = new JdbcTemplate(externalDataSource);
    }

    @Test
    @DisplayName("Должен экспортировать голову журнала во внешнее хранилище и подтвердить целостность")
    void shouldExportScopeHeadToExternalStoreAndVerifyIntegrity() {
        UUID userId = UUID.randomUUID();
        OffsetDateTime createdAt = OffsetDateTime.now().minusMinutes(1);
        insertActiveUser(userId, "anchor-success@example.test", createdAt);

        auditService.appendLoginSucceeded(userId, createdAt);

        List<AuditAnchorOutbox> pendingOutbox = auditAnchorOutboxRepository.findAll().stream()
                .filter(entry -> userId.equals(entry.getScopeId()))
                .toList();
        assertThat(pendingOutbox).hasSize(1);
        assertThat(pendingOutbox.get(0).getExportedAt()).isNull();

        AuditAnchorVerificationResponse beforeExport = auditAnchorService.verifyUserAnchor(userId);
        assertThat(beforeExport.anchorConfigured()).isTrue();
        assertThat(beforeExport.anchorPresent()).isFalse();
        assertThat(beforeExport.valid()).isFalse();

        auditAnchorExportJob.exportPendingAnchors();

        Long externalAnchorCount = externalAuditJdbcTemplate.queryForObject(
                """
                select count(*)
                from audit_anchors
                where source_instance_id = ?
                  and scope_type = 'USER'
                  and scope_id = ?
                """,
                Long.class,
                SOURCE_INSTANCE_ID,
                userId
        );

        assertThat(externalAnchorCount).isEqualTo(1L);

        AuditAnchorVerificationResponse verification = auditAnchorService.verifyUserAnchor(userId);
        AuditIntegrityResponse integrity = auditAnchorService.getUserIntegrity(userId);

        assertThat(verification.anchorConfigured()).isTrue();
        assertThat(verification.anchorPresent()).isTrue();
        assertThat(verification.anchorSignatureValid()).isTrue();
        assertThat(verification.anchoredEventPresentLocally()).isTrue();
        assertThat(verification.anchoredEventHashMatches()).isTrue();
        assertThat(verification.valid()).isTrue();
        assertThat(verification.problems()).isEmpty();

        assertThat(integrity.chainValid()).isTrue();
        assertThat(integrity.anchorValid()).isTrue();
        assertThat(integrity.valid()).isTrue();
        assertThat(integrity.totalEvents()).isEqualTo(1);
    }

    @Test
    @DisplayName("Должен обнаружить подмену внешнего якоря журнала")
    void shouldDetectTamperedExternalAnchor() {
        UUID userId = UUID.randomUUID();
        OffsetDateTime createdAt = OffsetDateTime.now().minusMinutes(1);
        insertActiveUser(userId, "anchor-tamper@example.test", createdAt);

        auditService.appendLogoutSucceeded(userId, createdAt);
        auditAnchorExportJob.exportPendingAnchors();

        externalAuditJdbcTemplate.update(
                """
                update audit_anchors
                   set event_hash = ?
                 where source_instance_id = ?
                   and scope_type = 'USER'
                   and scope_id = ?
                """,
                new byte[]{9, 9, 9, 9},
                SOURCE_INSTANCE_ID,
                userId
        );

        AuditAnchorVerificationResponse verification = auditAnchorService.verifyUserAnchor(userId);

        assertThat(verification.anchorPresent()).isTrue();
        assertThat(verification.anchorSignatureValid()).isTrue();
        assertThat(verification.anchoredEventPresentLocally()).isTrue();
        assertThat(verification.anchoredEventHashMatches()).isFalse();
        assertThat(verification.valid()).isFalse();
        assertThat(verification.problems())
                .anyMatch(problem -> problem.contains("eventHash mismatch"))
                .anyMatch(problem -> problem.contains("hash does not match"));
    }

    @Test
    @DisplayName("Должен восстанавливать пропущенную запись головы журнала в outbox")
    void shouldBackfillMissingHeadIntoOutbox() {
        UUID userId = UUID.randomUUID();
        OffsetDateTime createdAt = OffsetDateTime.now().minusMinutes(1);
        insertActiveUser(userId, "anchor-backfill@example.test", createdAt);

        auditService.appendRefreshSucceeded(userId, createdAt);

        jdbcClient.sql("""
                delete from audit_anchor_outbox
                where source_instance_id = ?
                  and scope_type = 'USER'
                  and scope_id = ?
                """)
                .params(SOURCE_INSTANCE_ID, userId)
                .update();

        assertThat(countOutboxRowsForUser(userId)).isZero();

        auditAnchorBackfillJob.backfillCurrentScopeHeadsIntoOutbox();

        assertThat(countOutboxRowsForUser(userId)).isEqualTo(1);
    }

    private void insertActiveUser(UUID userId, String email, OffsetDateTime now) {
        jdbcClient.sql("""
                insert into users (
                    user_id,
                    email,
                    status,
                    email_verified_at,
                    created_at,
                    updated_at
                ) values (?, ?, ?, ?, ?, ?)
                """)
                .params(userId, email, "ACTIVE", now, now, now)
                .update();
    }

    private long countOutboxRowsForUser(UUID userId) {
        Long count = jdbcClient.sql("""
                select count(*)
                from audit_anchor_outbox
                where source_instance_id = ?
                  and scope_type = 'USER'
                  and scope_id = ?
                """)
                .params(SOURCE_INSTANCE_ID, userId)
                .query(Long.class)
                .single();

        return count == null ? 0L : count;
    }
}
