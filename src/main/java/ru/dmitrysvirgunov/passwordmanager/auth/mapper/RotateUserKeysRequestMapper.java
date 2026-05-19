package ru.dmitrysvirgunov.passwordmanager.auth.mapper;

import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.Named;
import org.mapstruct.ReportingPolicy;
import ru.dmitrysvirgunov.passwordmanager.auth.dto.request.AeadParamsRequest;
import ru.dmitrysvirgunov.passwordmanager.auth.dto.request.AsymmetricKeyParamsRequest;
import ru.dmitrysvirgunov.passwordmanager.auth.dto.request.RotateUserKeysEnvelopeRequest;
import ru.dmitrysvirgunov.passwordmanager.auth.dto.request.RotateUserKeysRequest;
import ru.dmitrysvirgunov.passwordmanager.auth.model.AsymmetricKeyParams;
import ru.dmitrysvirgunov.passwordmanager.auth.model.RotateUserKeysEnvelopeInput;
import ru.dmitrysvirgunov.passwordmanager.auth.model.RotateUserKeysInput;
import ru.dmitrysvirgunov.passwordmanager.common.exception.InvalidRequestException;
import ru.dmitrysvirgunov.passwordmanager.common.model.AeadParams;

import java.util.Base64;

@Mapper(
        componentModel = "spring",
        unmappedTargetPolicy = ReportingPolicy.ERROR
)
public interface RotateUserKeysRequestMapper {

    @Mapping(target = "currentAuthSecret", source = "currentAuthSecretBase64", qualifiedByName = "decodeBase64")
    @Mapping(target = "publicEncryptionKey", source = "publicEncryptionKeyBase64", qualifiedByName = "decodeBase64")
    @Mapping(target = "encryptedPrivateEncryptionKey", source = "encryptedPrivateEncryptionKeyBase64", qualifiedByName = "decodeBase64")
    @Mapping(target = "publicSigningKey", source = "publicSigningKeyBase64", qualifiedByName = "decodeBase64")
    @Mapping(target = "encryptedPrivateSigningKey", source = "encryptedPrivateSigningKeyBase64", qualifiedByName = "decodeBase64")
    RotateUserKeysInput toInput(RotateUserKeysRequest request);

    @Mapping(target = "encryptedVaultKey", source = "encryptedVaultKeyBase64", qualifiedByName = "decodeBase64")
    RotateUserKeysEnvelopeInput toInput(RotateUserKeysEnvelopeRequest request);

    @Mapping(target = "iv", source = "ivBase64", qualifiedByName = "decodeBase64")
    AeadParams toModel(AeadParamsRequest request);

    AsymmetricKeyParams toModel(AsymmetricKeyParamsRequest request);

    @Named("decodeBase64")
    default byte[] decodeBase64(String value) {
        try {
            return Base64.getDecoder().decode(value);
        } catch (IllegalArgumentException e) {
            throw new InvalidRequestException("Invalid Base64 value", e);
        }
    }
}
