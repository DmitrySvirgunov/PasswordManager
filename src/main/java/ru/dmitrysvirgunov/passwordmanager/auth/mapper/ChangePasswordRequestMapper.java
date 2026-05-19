package ru.dmitrysvirgunov.passwordmanager.auth.mapper;

import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.Named;
import org.mapstruct.ReportingPolicy;
import ru.dmitrysvirgunov.passwordmanager.auth.dto.request.AeadParamsRequest;
import ru.dmitrysvirgunov.passwordmanager.auth.dto.request.ChangePasswordRequest;
import ru.dmitrysvirgunov.passwordmanager.auth.dto.request.KdfParamsRequest;
import ru.dmitrysvirgunov.passwordmanager.auth.model.ChangePasswordInput;
import ru.dmitrysvirgunov.passwordmanager.auth.model.KdfParams;
import ru.dmitrysvirgunov.passwordmanager.common.exception.InvalidRequestException;
import ru.dmitrysvirgunov.passwordmanager.common.model.AeadParams;

import java.util.Base64;

@Mapper(
        componentModel = "spring",
        unmappedTargetPolicy = ReportingPolicy.ERROR
)
public interface ChangePasswordRequestMapper {

    @Mapping(target = "currentAuthSecret", source = "currentAuthSecretBase64", qualifiedByName = "decodeBase64")
    @Mapping(target = "newAuthSecret", source = "newAuthSecretBase64", qualifiedByName = "decodeBase64")
    @Mapping(target = "newWrappedAccountRootKey", source = "newWrappedAccountRootKeyBase64", qualifiedByName = "decodeBase64")
    ChangePasswordInput toInput(ChangePasswordRequest request);

    @Mapping(target = "salt", source = "saltBase64", qualifiedByName = "decodeBase64")
    KdfParams toModel(KdfParamsRequest request);

    @Mapping(target = "iv", source = "ivBase64", qualifiedByName = "decodeBase64")
    AeadParams toModel(AeadParamsRequest request);

    @Named("decodeBase64")
    default byte[] decodeBase64(String value) {
        try {
            return Base64.getDecoder().decode(value);
        } catch (IllegalArgumentException e) {
            throw new InvalidRequestException("Invalid Base64 value", e);
        }
    }
}
