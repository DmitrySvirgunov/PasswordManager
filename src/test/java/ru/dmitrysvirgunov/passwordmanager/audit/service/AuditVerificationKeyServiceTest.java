package ru.dmitrysvirgunov.passwordmanager.audit.service;

import org.junit.jupiter.api.Test;
import ru.dmitrysvirgunov.passwordmanager.audit.config.AuditSigningProperties;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

class AuditVerificationKeyServiceTest {

    @Test
    void shouldReturnFalseForTamperedSignatureBytesInsteadOfThrowing() throws Exception {
        KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        AuditSigningProperties properties = new AuditSigningProperties();
        properties.setKeyId("sig-1");
        properties.setPublicKeyX509Base64(Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));

        AuditVerificationKeyService service = new AuditVerificationKeyService(properties);
        service.init();

        byte[] payload = new byte[]{1, 2, 3, 4};
        Signature signature = Signature.getInstance("Ed25519");
        signature.initSign(keyPair.getPrivate());
        signature.update(payload);
        byte[] validSignature = signature.sign();
        byte[] tamperedSignature = new byte[]{validSignature[0]};

        assertThat(service.verify("sig-1", payload, tamperedSignature)).isFalse();
    }
}
