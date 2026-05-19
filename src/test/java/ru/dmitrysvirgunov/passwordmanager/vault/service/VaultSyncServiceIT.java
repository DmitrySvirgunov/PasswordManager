package ru.dmitrysvirgunov.passwordmanager.vault.service;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.testcontainers.junit.jupiter.Testcontainers;
import ru.dmitrysvirgunov.passwordmanager.support.AbstractPostgresIntegrationTest;
import ru.dmitrysvirgunov.passwordmanager.vault.dto.response.sync.GetUserSyncResponse;
import ru.dmitrysvirgunov.passwordmanager.vault.dto.response.sync.GetVaultSyncResponse;
import ru.dmitrysvirgunov.passwordmanager.vault.model.SyncOpType;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("Интеграционные тесты синхронизации сейфа")
@Testcontainers
class VaultSyncServiceIT extends AbstractPostgresIntegrationTest {

    @Autowired
    private JdbcClient jdbcClient;

    @Autowired
    private VaultSyncService vaultSyncService;

    @Test
    @DisplayName("Должен возвращать события сейфа по порядку после указанной последовательности")
    void shouldReturnVaultSyncEventsOrderedAfterRequestedSequence() {
        UUID ownerId = UUID.randomUUID();
        UUID vaultId = UUID.randomUUID();
        UUID objectIdOne = UUID.randomUUID();
        UUID objectIdTwo = UUID.randomUUID();
        OffsetDateTime now = OffsetDateTime.now().minusMinutes(1);

        insertActiveUser(ownerId, "sync-owner@example.test", now);
        insertVault(vaultId, ownerId, now);
        insertActiveMembership(vaultId, ownerId, now);
        insertVaultObject(objectIdOne, vaultId, 1, false, now);
        insertVaultObject(objectIdTwo, vaultId, 2, true, now.plusSeconds(5));

        vaultSyncService.appendUpsert(vaultId, objectIdOne, 1, ownerId, now.plusSeconds(10));
        vaultSyncService.appendDelete(vaultId, objectIdTwo, 2, ownerId, now.plusSeconds(20));

        GetVaultSyncResponse response = vaultSyncService.getVaultSync(vaultId, 0L, jwt(ownerId));

        assertThat(response.afterSeq()).isZero();
        assertThat(response.lastSeq()).isEqualTo(2L);
        assertThat(response.events())
                .extracting(event -> event.objectId(), event -> event.version(), event -> event.opType())
                .containsExactly(
                        org.assertj.core.groups.Tuple.tuple(objectIdOne, 1, SyncOpType.UPSERT),
                        org.assertj.core.groups.Tuple.tuple(objectIdTwo, 2, SyncOpType.DELETE)
                );
    }

    @Test
    @DisplayName("Должен возвращать целевые пользовательские события синхронизации и ссылку на удаленный сейф")
    void shouldReturnTargetedUserSyncEventsIncludingDeletedVaultReference() {
        UUID ownerId = UUID.randomUUID();
        UUID targetUserId = UUID.randomUUID();
        UUID vaultId = UUID.randomUUID();
        UUID inviteId = UUID.randomUUID();
        OffsetDateTime now = OffsetDateTime.now().minusMinutes(1);

        insertActiveUser(ownerId, "sync-actor@example.test", now);
        insertActiveUser(targetUserId, "sync-target@example.test", now);
        insertVault(vaultId, ownerId, now);
        insertPendingInvite(inviteId, vaultId, ownerId, targetUserId, now);

        vaultSyncService.appendTargetedMembershipChanged(
                vaultId,
                targetUserId,
                inviteId,
                ownerId,
                now.plusSeconds(10)
        );
        vaultSyncService.appendTargetedVaultDeleted(
                vaultId,
                targetUserId,
                ownerId,
                now.plusSeconds(20)
        );

        GetUserSyncResponse response = vaultSyncService.getUserSync(0L, jwt(targetUserId));

        assertThat(response.afterSeq()).isZero();
        assertThat(response.lastSeq()).isEqualTo(2L);
        assertThat(response.events())
                .extracting(event -> event.vaultId(), event -> event.inviteId(), event -> event.opType())
                .containsExactly(
                        org.assertj.core.groups.Tuple.tuple(vaultId, inviteId, SyncOpType.MEMBERSHIP_CHANGED),
                        org.assertj.core.groups.Tuple.tuple(vaultId, null, SyncOpType.VAULT_DELETED)
                );
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

    private void insertVault(UUID vaultId, UUID ownerId, OffsetDateTime now) {
        jdbcClient.sql("""
                insert into vaults (
                    vault_id,
                    created_by_user_id,
                    name_ciphertext,
                    name_aead_params,
                    vault_version,
                    current_vault_key_version,
                    created_at,
                    updated_at
                ) values (?, ?, ?, cast(? as jsonb), ?, ?, ?, ?)
                """)
                .params(vaultId, ownerId, new byte[]{1}, "{}", 1, 1, now, now)
                .update();
    }

    private void insertActiveMembership(UUID vaultId, UUID userId, OffsetDateTime now) {
        jdbcClient.sql("""
                insert into vault_members (
                    vault_id,
                    user_id,
                    role,
                    status,
                    joined_at,
                    revoked_at,
                    expires_at
                ) values (?, ?, ?, ?, ?, ?, ?)
                """)
                .params(vaultId, userId, "OWNER", "ACTIVE", now, null, null)
                .update();
    }

    private void insertVaultObject(
            UUID objectId,
            UUID vaultId,
            int currentVersion,
            boolean deleted,
            OffsetDateTime now
    ) {
        jdbcClient.sql("""
                insert into vault_objects (
                    object_id,
                    vault_id,
                    current_version,
                    deleted,
                    created_at,
                    updated_at
                ) values (?, ?, ?, ?, ?, ?)
                """)
                .params(objectId, vaultId, currentVersion, deleted, now, now)
                .update();
    }

    private void insertPendingInvite(
            UUID inviteId,
            UUID vaultId,
            UUID ownerId,
            UUID targetUserId,
            OffsetDateTime now
    ) {
        jdbcClient.sql("""
                insert into vault_invites (
                    invite_id,
                    vault_id,
                    created_by_user_id,
                    invitee_user_id,
                    invitee_email,
                    role,
                    status,
                    created_at,
                    expires_at,
                    accepted_at,
                    revoked_at
                ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """)
                .params(
                        inviteId,
                        vaultId,
                        ownerId,
                        targetUserId,
                        "sync-target@example.test",
                        "EDITOR",
                        "PENDING",
                        now,
                        now.plusDays(7),
                        null,
                        null
                )
                .update();
    }

    private Jwt jwt(UUID userId) {
        Instant issuedAt = Instant.now();
        return new Jwt(
                "token-" + userId,
                issuedAt,
                issuedAt.plusSeconds(300),
                Map.of("alg", "none"),
                Map.of("sub", userId.toString())
        );
    }
}
