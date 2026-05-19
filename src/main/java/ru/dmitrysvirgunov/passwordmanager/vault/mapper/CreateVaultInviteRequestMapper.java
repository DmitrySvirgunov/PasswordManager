package ru.dmitrysvirgunov.passwordmanager.vault.mapper;

import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.Named;
import org.mapstruct.ReportingPolicy;
import ru.dmitrysvirgunov.passwordmanager.common.exception.InvalidRequestException;
import ru.dmitrysvirgunov.passwordmanager.vault.dto.request.CreateVaultInviteRequest;
import ru.dmitrysvirgunov.passwordmanager.vault.model.CreateVaultInviteInput;

import java.util.Base64;

@Mapper(
        componentModel = "spring",
        unmappedTargetPolicy = ReportingPolicy.ERROR
)
public interface CreateVaultInviteRequestMapper {

    @Mapping(target = "encryptedVaultKey", source = "encryptedVaultKeyBase64", qualifiedByName = "decodeBase64")
    CreateVaultInviteInput toInput(CreateVaultInviteRequest request);

    @Named("decodeBase64")
    default byte[] decodeBase64(String value) {
        try {
            return Base64.getDecoder().decode(value);
        } catch (IllegalArgumentException e) {
            throw new InvalidRequestException("Invalid Base64 value", e);
        }
    }
}