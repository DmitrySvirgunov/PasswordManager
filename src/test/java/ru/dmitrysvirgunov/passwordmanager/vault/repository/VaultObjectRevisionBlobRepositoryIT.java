package ru.dmitrysvirgunov.passwordmanager.vault.repository;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.simple.JdbcClient;
import ru.dmitrysvirgunov.passwordmanager.support.AbstractPostgresIntegrationTest;

import java.time.OffsetDateTime;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class VaultObjectRevisionBlobRepositoryIT extends AbstractPostgresIntegrationTest {

    @Autowired
    private JdbcClient jdbcClient;

    @Autowired
    private VaultObjectRevisionBlobRepository vaultObjectRevisionBlobRepository;

    @Test
    void shouldDeleteRevisionBlobLinksBeforeDeletingVaultAggregate() {
        UUID userId = UUID.randomUUID();
        UUID vaultId = UUID.randomUUID();
        UUID objectId = UUID.randomUUID();
        UUID revisionId = UUID.randomUUID();
        UUID blobId = UUID.randomUUID();
        OffsetDateTime now = OffsetDateTime.now();

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
                .params(userId, "owner@example.test", "ACTIVE", now, now, now)
                .update();

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
                .params(vaultId, userId, new byte[]{1}, "{}", 1, 1, now, now)
                .update();

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
                .params(objectId, vaultId, 1, false, now, now)
                .update();

        jdbcClient.sql("""
                insert into vault_object_revisions (
                    revision_id,
                    object_id,
                    version,
                    ciphertext,
                    content_aead_params,
                    wrapped_record_key,
                    record_key_wrap_params,
                    record_key_wrapped_by_vault_key_version,
                    encrypted_package_hash,
                    client_signature,
                    signature_key_version,
                    signed_by_user_id,
                    created_at
                ) values (?, ?, ?, ?, cast(? as jsonb), ?, cast(? as jsonb), ?, ?, ?, ?, ?, ?)
                """)
                .params(
                        revisionId,
                        objectId,
                        1,
                        new byte[]{2},
                        "{}",
                        new byte[]{3},
                        "{}",
                        1,
                        new byte[]{4},
                        new byte[]{5},
                        1,
                        userId,
                        now
                )
                .update();

        jdbcClient.sql("""
                insert into vault_blobs (
                    blob_id,
                    vault_id,
                    status,
                    ciphertext_size_bytes,
                    chunk_size_bytes,
                    chunk_count,
                    ciphertext_sha256,
                    created_by_user_id,
                    created_at,
                    completed_at
                ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """)
                .params(blobId, vaultId, "READY", 1L, 1, 1, new byte[]{6}, userId, now, now)
                .update();

        jdbcClient.sql("""
                insert into vault_object_revision_blobs (
                    revision_id,
                    role,
                    blob_id,
                    created_at
                ) values (?, ?, ?, ?)
                """)
                .params(revisionId, "PRIMARY", blobId, now)
                .update();

        int deletedLinks = vaultObjectRevisionBlobRepository.deleteByVaultId(vaultId);

        assertThat(deletedLinks).isEqualTo(1);

        jdbcClient.sql("delete from vaults where vault_id = ?")
                .param(vaultId)
                .update();

        assertThat(countRows("vaults", "vault_id", vaultId)).isZero();
        assertThat(countRows("vault_objects", "vault_id", vaultId)).isZero();
        assertThat(countRows("vault_object_revisions", "revision_id", revisionId)).isZero();
        assertThat(countRows("vault_blobs", "vault_id", vaultId)).isZero();
        assertThat(countRows("vault_object_revision_blobs", "revision_id", revisionId)).isZero();
    }

    private long countRows(String tableName, String columnName, UUID id) {
        return jdbcClient.sql("select count(*) from " + tableName + " where " + columnName + " = ?")
                .param(id)
                .query(Long.class)
                .single();
    }
}
