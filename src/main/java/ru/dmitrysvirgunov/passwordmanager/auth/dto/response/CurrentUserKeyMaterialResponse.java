package ru.dmitrysvirgunov.passwordmanager.auth.dto.response;

import java.time.OffsetDateTime;

public record CurrentUserKeyMaterialResponse(
        String wrappedAccountRootKeyBase64,
        AeadParamsResponse accountRootWrapParams,
        Integer accountRootVersion,

        String publicEncryptionKeyBase64,
        String encryptedPrivateEncryptionKeyBase64,
        AsymmetricKeyParamsResponse encryptionKeyParams,
        Integer encryptionKeyVersion,

        String publicSigningKeyBase64,
        String encryptedPrivateSigningKeyBase64,
        AsymmetricKeyParamsResponse signingKeyParams,
        Integer signingKeyVersion,

        OffsetDateTime rotatedAt
) {
}
