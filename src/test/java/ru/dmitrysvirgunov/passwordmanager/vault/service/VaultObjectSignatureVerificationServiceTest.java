package ru.dmitrysvirgunov.passwordmanager.vault.service;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import ru.dmitrysvirgunov.passwordmanager.auth.entity.UserKeyMaterial;
import ru.dmitrysvirgunov.passwordmanager.auth.repository.UserKeyMaterialHistoryRepository;
import ru.dmitrysvirgunov.passwordmanager.auth.repository.UserKeyMaterialRepository;
import ru.dmitrysvirgunov.passwordmanager.common.exception.ConflictException;
import ru.dmitrysvirgunov.passwordmanager.common.exception.InvalidRequestException;
import ru.dmitrysvirgunov.passwordmanager.common.model.AeadParams;
import ru.dmitrysvirgunov.passwordmanager.vault.dto.response.object.VaultObjectSignatureVerificationStatus;
import ru.dmitrysvirgunov.passwordmanager.vault.entity.VaultObjectRevision;
import ru.dmitrysvirgunov.passwordmanager.vault.model.BlobReferenceInput;
import ru.dmitrysvirgunov.passwordmanager.vault.model.VaultBlobReferenceRole;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.time.OffsetDateTime;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@DisplayName("Проверка подписей ревизий объектов сейфа")
class VaultObjectSignatureVerificationServiceTest {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    @Mock
    private UserKeyMaterialRepository userKeyMaterialRepository;

    @Mock
    private UserKeyMaterialHistoryRepository userKeyMaterialHistoryRepository;

    @InjectMocks
    private VaultObjectSignatureVerificationService vaultObjectSignatureVerificationService;

    @Test
    @DisplayName("Должен принимать корректно подписанный запрос с текущей версией ключа подписи")
    void shouldVerifyWritablePayloadUsingCurrentSigningKey() throws Exception {
        KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        UUID userId = UUID.randomUUID();

        VaultObjectSignaturePayload payload = buildPayload(keyPair);
        UserKeyMaterial keyMaterial = UserKeyMaterial.builder()
                .userId(userId)
                .wrappedAccountRootKey(new byte[]{1})
                .accountRootWrapParams(new AeadParams("AES-GCM", new byte[]{1}))
                .accountRootVersion(1)
                .publicEncryptionKey(new byte[]{1})
                .encryptedPrivateEncryptionKey(new byte[]{1})
                .encryptionKeyParams(null)
                .encryptionKeyVersion(1)
                .publicSigningKey(keyPair.getPublic().getEncoded())
                .encryptedPrivateSigningKey(new byte[]{1})
                .signingKeyParams(null)
                .signingKeyVersion(payload.signatureKeyVersion())
                .createdAt(OffsetDateTime.now())
                .build();

        when(userKeyMaterialRepository.findById(userId)).thenReturn(Optional.of(keyMaterial));

        assertThatCode(() ->
                vaultObjectSignatureVerificationService.verifyWritablePayload(userId, payload)
        ).doesNotThrowAnyException();
    }

    @Test
    @DisplayName("Должен отклонять запрос со старой версией ключа подписи")
    void shouldRejectWhenRequestUsesStaleSigningKeyVersion() throws Exception {
        KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        UUID userId = UUID.randomUUID();

        VaultObjectSignaturePayload payload = buildPayload(keyPair);
        UserKeyMaterial keyMaterial = UserKeyMaterial.builder()
                .userId(userId)
                .wrappedAccountRootKey(new byte[]{1})
                .accountRootWrapParams(new AeadParams("AES-GCM", new byte[]{1}))
                .accountRootVersion(1)
                .publicEncryptionKey(new byte[]{1})
                .encryptedPrivateEncryptionKey(new byte[]{1})
                .encryptionKeyParams(null)
                .encryptionKeyVersion(1)
                .publicSigningKey(keyPair.getPublic().getEncoded())
                .encryptedPrivateSigningKey(new byte[]{1})
                .signingKeyParams(null)
                .signingKeyVersion(payload.signatureKeyVersion() + 1)
                .createdAt(OffsetDateTime.now())
                .build();

        when(userKeyMaterialRepository.findById(userId)).thenReturn(Optional.of(keyMaterial));

        assertThatThrownBy(() ->
                vaultObjectSignatureVerificationService.verifyWritablePayload(userId, payload)
        ).isInstanceOf(ConflictException.class);
    }

    @Test
    @DisplayName("Должен отклонять запрос с поврежденной подписью")
    void shouldRejectWhenSignatureIsTampered() throws Exception {
        KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        UUID userId = UUID.randomUUID();

        VaultObjectSignaturePayload payload = buildPayload(keyPair);
        byte[] tamperedSignature = payload.clientSignature().clone();
        tamperedSignature[0] ^= 0x01;

        UserKeyMaterial keyMaterial = UserKeyMaterial.builder()
                .userId(userId)
                .wrappedAccountRootKey(new byte[]{1})
                .accountRootWrapParams(new AeadParams("AES-GCM", new byte[]{1}))
                .accountRootVersion(1)
                .publicEncryptionKey(new byte[]{1})
                .encryptedPrivateEncryptionKey(new byte[]{1})
                .encryptionKeyParams(null)
                .encryptionKeyVersion(1)
                .publicSigningKey(keyPair.getPublic().getEncoded())
                .encryptedPrivateSigningKey(new byte[]{1})
                .signingKeyParams(null)
                .signingKeyVersion(payload.signatureKeyVersion())
                .createdAt(OffsetDateTime.now())
                .build();

        when(userKeyMaterialRepository.findById(userId)).thenReturn(Optional.of(keyMaterial));

        assertThatThrownBy(() ->
                vaultObjectSignatureVerificationService.verifyWritablePayload(
                        userId,
                        new VaultObjectSignaturePayload(
                                payload.ciphertext(),
                                payload.contentAeadParams(),
                                payload.wrappedRecordKey(),
                                payload.recordKeyWrapParams(),
                                payload.encryptedPackageHash(),
                                tamperedSignature,
                                payload.signatureKeyVersion(),
                                payload.signatureFormatVersion(),
                                payload.blobReferences()
                        )
                )
        ).isInstanceOf(InvalidRequestException.class)
                .hasMessage("Vault object signature verification failed");
    }

    @Test
    @DisplayName("Должен помечать старую ревизию как непроверяемую по новой схеме")
    void shouldMarkLegacyRevisionAsUnverified() {
        VaultObjectRevision revision = VaultObjectRevision.builder()
                .revisionId(UUID.randomUUID())
                .objectId(UUID.randomUUID())
                .version(1)
                .ciphertext(new byte[]{1})
                .contentAeadParams(new AeadParams("AES-GCM", new byte[]{1}))
                .wrappedRecordKey(new byte[]{2})
                .recordKeyWrapParams(OBJECT_MAPPER.createObjectNode())
                .encryptedPackageHash(new byte[]{3})
                .clientSignature(new byte[]{4})
                .signatureFormatVersion(1)
                .signatureKeyVersion(1)
                .createdAt(OffsetDateTime.now())
                .build();

        assertThat(
                vaultObjectSignatureVerificationService.verifyRevision(revision, List.of()).status()
        ).isEqualTo(VaultObjectSignatureVerificationStatus.LEGACY_UNVERIFIED);
    }

    private VaultObjectSignaturePayload buildPayload(KeyPair keyPair) throws Exception {
        ObjectNode recordKeyWrapParams = OBJECT_MAPPER.createObjectNode();
        recordKeyWrapParams.put("algorithm", "AES-GCM");
        recordKeyWrapParams.put("ivBase64", Base64.getEncoder().encodeToString(new byte[]{7, 8, 9}));

        VaultObjectSignaturePayload unsignedPayload = new VaultObjectSignaturePayload(
                new byte[]{10, 11, 12},
                new AeadParams("AES-GCM", new byte[]{1, 2, 3}),
                new byte[]{20, 21, 22},
                recordKeyWrapParams,
                new byte[0],
                new byte[0],
                3,
                VaultObjectSignatureV2.FORMAT_VERSION,
                List.of(new BlobReferenceInput(UUID.randomUUID(), VaultBlobReferenceRole.PRIMARY))
        );

        byte[] canonicalBytes = VaultObjectSignatureV2.buildCanonicalBytes(unsignedPayload);
        byte[] hash = MessageDigest.getInstance("SHA-256").digest(canonicalBytes);

        Signature signature = Signature.getInstance("Ed25519");
        signature.initSign(keyPair.getPrivate());
        signature.update(hash);

        return new VaultObjectSignaturePayload(
                unsignedPayload.ciphertext(),
                unsignedPayload.contentAeadParams(),
                unsignedPayload.wrappedRecordKey(),
                unsignedPayload.recordKeyWrapParams(),
                hash,
                signature.sign(),
                unsignedPayload.signatureKeyVersion(),
                unsignedPayload.signatureFormatVersion(),
                unsignedPayload.blobReferences()
        );
    }
}
