package ru.dmitrysvirgunov.passwordmanager.auth.mapper;

import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.Named;
import org.mapstruct.ReportingPolicy;
import ru.dmitrysvirgunov.passwordmanager.auth.dto.request.AeadParamsRequest;
import ru.dmitrysvirgunov.passwordmanager.auth.dto.request.AsymmetricKeyParamsRequest;
import ru.dmitrysvirgunov.passwordmanager.auth.dto.request.KdfParamsRequest;
import ru.dmitrysvirgunov.passwordmanager.auth.dto.request.RegisterRequest;
import ru.dmitrysvirgunov.passwordmanager.common.model.AeadParams;
import ru.dmitrysvirgunov.passwordmanager.auth.model.AsymmetricKeyParams;
import ru.dmitrysvirgunov.passwordmanager.auth.model.KdfParams;
import ru.dmitrysvirgunov.passwordmanager.auth.model.RegisterInput;
import ru.dmitrysvirgunov.passwordmanager.common.exception.InvalidRequestException;

import java.util.Base64;
import java.util.Locale;

@Mapper(
        componentModel = "spring",
        unmappedTargetPolicy = ReportingPolicy.ERROR
)
public interface RegisterRequestMapper {

    @Mapping(target = "email", source = "email", qualifiedByName = "normalizeEmail")
    @Mapping(target = "authSecret", source = "authSecretBase64", qualifiedByName = "decodeBase64")

    @Mapping(target = "wrappedAccountRootKey", source = "wrappedAccountRootKeyBase64", qualifiedByName = "decodeBase64")

    @Mapping(target = "publicEncryptionKey", source = "publicEncryptionKeyBase64", qualifiedByName = "decodeBase64")
    @Mapping(target = "encryptedPrivateEncryptionKey", source = "encryptedPrivateEncryptionKeyBase64", qualifiedByName = "decodeBase64")

    @Mapping(target = "publicSigningKey", source = "publicSigningKeyBase64", qualifiedByName = "decodeBase64")
    @Mapping(target = "encryptedPrivateSigningKey", source = "encryptedPrivateSigningKeyBase64", qualifiedByName = "decodeBase64")
    RegisterInput toInput(RegisterRequest request);

    @Mapping(target = "salt", source = "saltBase64", qualifiedByName = "decodeBase64")
    KdfParams toModel(KdfParamsRequest request);

    @Mapping(target = "iv", source = "ivBase64", qualifiedByName = "decodeBase64")
    AeadParams toModel(AeadParamsRequest request);

    AsymmetricKeyParams toModel(AsymmetricKeyParamsRequest request);

    @Named("normalizeEmail")
    default String normalizeEmail(String email) {
        return email.trim().toLowerCase(Locale.ROOT);
    }

    @Named("decodeBase64")
    default byte[] decodeBase64(String value) {
        try {
            return Base64.getDecoder().decode(value);
        } catch (IllegalArgumentException e) {
            throw new InvalidRequestException("Invalid Base64 value", e);
        }
    }
}