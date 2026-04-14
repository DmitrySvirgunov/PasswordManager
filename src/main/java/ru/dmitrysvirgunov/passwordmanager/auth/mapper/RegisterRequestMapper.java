package ru.dmitrysvirgunov.passwordmanager.auth.mapper;

import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.Named;
import org.mapstruct.ReportingPolicy;
import ru.dmitrysvirgunov.passwordmanager.auth.dto.request.KeyParamsRequest;
import ru.dmitrysvirgunov.passwordmanager.auth.dto.request.KdfParamsRequest;
import ru.dmitrysvirgunov.passwordmanager.auth.dto.request.RegisterRequest;
import ru.dmitrysvirgunov.passwordmanager.auth.model.RegisterInput;
import ru.dmitrysvirgunov.passwordmanager.auth.model.KdfParams;
import ru.dmitrysvirgunov.passwordmanager.auth.model.KeyParams;
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
    @Mapping(target = "clientKdfParams", source = "clientKdfParams")
    @Mapping(target = "publicKey", source = "publicKeyBase64", qualifiedByName = "decodeBase64")
    @Mapping(target = "encryptedPrivateKey", source = "encryptedPrivateKeyBase64", qualifiedByName = "decodeBase64")
    RegisterInput toInput(RegisterRequest request);

    @Mapping(target = "salt", source = "saltBase64", qualifiedByName = "decodeBase64")
    KdfParams toKdfParams(KdfParamsRequest dto);

    @Mapping(target = "privateKeyWrapAlgorithm", source = "privateKeyWrap.algorithm")
    @Mapping(target = "privateKeyWrapIv", source = "privateKeyWrap.ivBase64", qualifiedByName = "decodeBase64")
    @Mapping(target = "privateKeyWrapSalt", source = "privateKeyWrap.saltBase64", qualifiedByName = "decodeBase64")
    KeyParams toKeyParams(KeyParamsRequest dto);

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
