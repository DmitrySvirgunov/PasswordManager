package ru.dmitrysvirgunov.passwordmanager.audit.service;

import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import ru.dmitrysvirgunov.passwordmanager.audit.config.AuditSigningProperties;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

@Service
@RequiredArgsConstructor
public class AuditSigningService {

    private final AuditSigningProperties properties;

    private PrivateKey privateKey;

    @PostConstruct
    void init() {
        try {
            if (properties.getKeyId() == null || properties.getKeyId().isBlank()) {
                throw new IllegalStateException("Audit signing keyId is not configured");
            }

            if (properties.getPrivateKeyPkcs8Base64() == null || properties.getPrivateKeyPkcs8Base64().isBlank()) {
                throw new IllegalStateException("Audit signing private key is not configured");
            }

            KeyFactory keyFactory = KeyFactory.getInstance("Ed25519");
            byte[] privateKeyBytes = Base64.getDecoder().decode(properties.getPrivateKeyPkcs8Base64());

            this.privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));
        } catch (Exception e) {
            throw new IllegalStateException("Failed to initialize audit signing key", e);
        }
    }

    public String keyId() {
        return properties.getKeyId();
    }

    public byte[] sign(byte[] payload) {
        try {
            Signature signature = Signature.getInstance("Ed25519");
            signature.initSign(privateKey);
            signature.update(payload);
            return signature.sign();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to sign audit payload", e);
        }
    }
}