package ru.dmitrysvirgunov.passwordmanager.audit.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Getter
@Setter
@Component
@ConfigurationProperties(prefix = "app.audit.signing")
public class AuditSigningProperties {

    private String keyId;
    private String privateKeyPkcs8Base64;
    private String publicKeyX509Base64;

    private List<TrustedPublicKey> trustedPublicKeys = new ArrayList<>();

    @Getter
    @Setter
    public static class TrustedPublicKey {
        private String keyId;
        private String publicKeyX509Base64;
    }
}