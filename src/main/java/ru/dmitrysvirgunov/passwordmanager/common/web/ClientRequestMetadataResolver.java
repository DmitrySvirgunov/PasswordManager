package ru.dmitrysvirgunov.passwordmanager.common.web;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Component;

@Component
public class ClientRequestMetadataResolver {

    public ClientRequestMetadata resolve(HttpServletRequest request) {
        return new ClientRequestMetadata(
                request.getRemoteAddr(),
                request.getHeader("User-Agent")
        );
    }
}
