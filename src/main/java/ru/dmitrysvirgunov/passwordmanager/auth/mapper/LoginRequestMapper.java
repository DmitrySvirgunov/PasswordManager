package ru.dmitrysvirgunov.passwordmanager.auth.mapper;

import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.Named;
import org.mapstruct.ReportingPolicy;
import ru.dmitrysvirgunov.passwordmanager.auth.dto.request.LoginRequest;
import ru.dmitrysvirgunov.passwordmanager.auth.model.LoginInput;
import ru.dmitrysvirgunov.passwordmanager.common.exception.InvalidRequestException;

import java.util.Base64;
import java.util.Locale;

@Mapper(
        componentModel = "spring",
        unmappedTargetPolicy = ReportingPolicy.ERROR
)
public interface LoginRequestMapper {

    @Mapping(target = "email", source = "email", qualifiedByName = "normalizeEmail")
    @Mapping(target = "authSecret", source = "authSecretBase64", qualifiedByName = "decodeBase64")
    LoginInput toInput(LoginRequest request);

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
