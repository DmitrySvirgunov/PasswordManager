package ru.dmitrysvirgunov.passwordmanager.common.web;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Component;
import ru.dmitrysvirgunov.passwordmanager.auth.model.RegistrationRequestMetadata;

@Component
public class ClientRequestMetadataResolver {

    public RegistrationRequestMetadata resolve(HttpServletRequest request) {
        return new RegistrationRequestMetadata(
                request.getRemoteAddr(),
                request.getHeader("User-Agent")
        );
    }
}