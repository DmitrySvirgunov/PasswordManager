package ru.dmitrysvirgunov.passwordmanager.auth.mapper;

import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.Named;
import org.mapstruct.ReportingPolicy;
import ru.dmitrysvirgunov.passwordmanager.auth.dto.request.DeleteAccountRequest;
import ru.dmitrysvirgunov.passwordmanager.auth.model.DeleteAccountInput;
import ru.dmitrysvirgunov.passwordmanager.common.exception.InvalidRequestException;

import java.util.Base64;

@Mapper(
        componentModel = "spring",
        unmappedTargetPolicy = ReportingPolicy.ERROR
)
public interface DeleteAccountRequestMapper {

    @Mapping(target = "currentAuthSecret", source = "currentAuthSecretBase64", qualifiedByName = "decodeBase64")
    DeleteAccountInput toInput(DeleteAccountRequest request);

    @Named("decodeBase64")
    default byte[] decodeBase64(String value) {
        try {
            return Base64.getDecoder().decode(value);
        } catch (IllegalArgumentException e) {
            throw new InvalidRequestException("Invalid Base64 value", e);
        }
    }
}
