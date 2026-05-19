package ru.dmitrysvirgunov.passwordmanager.auth.mapper;

import org.springframework.stereotype.Component;
import ru.dmitrysvirgunov.passwordmanager.auth.dto.response.AeadParamsResponse;
import ru.dmitrysvirgunov.passwordmanager.auth.dto.response.AsymmetricKeyParamsResponse;
import ru.dmitrysvirgunov.passwordmanager.auth.dto.response.CurrentUserKeyMaterialResponse;
import ru.dmitrysvirgunov.passwordmanager.auth.entity.UserKeyMaterial;
import ru.dmitrysvirgunov.passwordmanager.auth.model.AsymmetricKeyParams;
import ru.dmitrysvirgunov.passwordmanager.common.model.AeadParams;

import java.util.Base64;

@Component
public class AuthResponseMapper {

    public CurrentUserKeyMaterialResponse toCurrentUserKeyMaterialResponse(UserKeyMaterial keyMaterial) {
        return new CurrentUserKeyMaterialResponse(
                encodeBase64(keyMaterial.getWrappedAccountRootKey()),
                toAeadParamsResponse(keyMaterial.getAccountRootWrapParams()),
                keyMaterial.getAccountRootVersion(),

                encodeBase64(keyMaterial.getPublicEncryptionKey()),
                encodeBase64(keyMaterial.getEncryptedPrivateEncryptionKey()),
                toAsymmetricKeyParamsResponse(keyMaterial.getEncryptionKeyParams()),
                keyMaterial.getEncryptionKeyVersion(),

                encodeBase64(keyMaterial.getPublicSigningKey()),
                encodeBase64(keyMaterial.getEncryptedPrivateSigningKey()),
                toAsymmetricKeyParamsResponse(keyMaterial.getSigningKeyParams()),
                keyMaterial.getSigningKeyVersion(),
                keyMaterial.getRotatedAt()
        );
    }

    public AeadParamsResponse toAeadParamsResponse(AeadParams params) {
        if (params == null) {
            return null;
        }

        return new AeadParamsResponse(
                params.algorithm(),
                encodeBase64(params.iv())
        );
    }

    public AsymmetricKeyParamsResponse toAsymmetricKeyParamsResponse(AsymmetricKeyParams params) {
        if (params == null) {
            return null;
        }

        return new AsymmetricKeyParamsResponse(
                params.keyAlgorithm(),
                params.publicKeyEncoding(),
                params.privateKeyEncoding(),
                toAeadParamsResponse(params.privateKeyWrap())
        );
    }

    private String encodeBase64(byte[] value) {
        if (value == null) {
            return null;
        }

        return Base64.getEncoder().encodeToString(value);
    }
}
