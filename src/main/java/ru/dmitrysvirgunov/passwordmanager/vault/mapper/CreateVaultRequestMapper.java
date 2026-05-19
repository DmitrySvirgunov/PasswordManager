package ru.dmitrysvirgunov.passwordmanager.vault.mapper;

import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.Named;
import org.mapstruct.ReportingPolicy;
import ru.dmitrysvirgunov.passwordmanager.auth.dto.request.AeadParamsRequest;
import ru.dmitrysvirgunov.passwordmanager.common.exception.InvalidRequestException;
import ru.dmitrysvirgunov.passwordmanager.common.model.AeadParams;
import ru.dmitrysvirgunov.passwordmanager.vault.dto.request.CreateVaultRequest;
import ru.dmitrysvirgunov.passwordmanager.vault.model.CreateVaultInput;

import java.util.Base64;

@Mapper(
        componentModel = "spring",
        unmappedTargetPolicy = ReportingPolicy.ERROR
)
public interface CreateVaultRequestMapper {

    @Mapping(target = "nameCiphertext", source = "nameCiphertextBase64", qualifiedByName = "decodeBase64")
    @Mapping(target = "encryptedVaultKey", source = "encryptedVaultKeyBase64", qualifiedByName = "decodeBase64")
    CreateVaultInput toInput(CreateVaultRequest request);

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