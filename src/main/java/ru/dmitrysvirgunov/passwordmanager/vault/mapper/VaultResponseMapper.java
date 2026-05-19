package ru.dmitrysvirgunov.passwordmanager.vault.mapper;

import org.springframework.stereotype.Component;
import ru.dmitrysvirgunov.passwordmanager.vault.dto.response.vault.VaultDetailsResponse;
import ru.dmitrysvirgunov.passwordmanager.vault.dto.response.vault.VaultEnvelopeResponse;
import ru.dmitrysvirgunov.passwordmanager.vault.dto.response.vault.VaultSummaryResponse;
import ru.dmitrysvirgunov.passwordmanager.vault.entity.Vault;
import ru.dmitrysvirgunov.passwordmanager.vault.entity.VaultKeyEnvelope;
import ru.dmitrysvirgunov.passwordmanager.vault.entity.VaultMember;

import java.util.Base64;

@Component
public class VaultResponseMapper {

    public VaultSummaryResponse toSummaryResponse(
            Vault vault,
            VaultMember membership,
            VaultKeyEnvelope envelope
    ) {
        Base64.Encoder encoder = Base64.getEncoder();

        VaultEnvelopeResponse envelopeResponse = toEnvelopeResponse(envelope);

        return new VaultSummaryResponse(
                vault.getVaultId(),
                encoder.encodeToString(vault.getNameCiphertext()),
                vault.getNameAeadParams(),
                vault.getVaultVersion(),
                vault.getCurrentVaultKeyVersion(),
                membership.getRole(),
                membership.getStatus(),
                membership.getJoinedAt(),
                vault.getUpdatedAt(),
                envelopeResponse
        );
    }

    public VaultDetailsResponse toDetailsResponse(
            Vault vault,
            VaultMember membership,
            VaultKeyEnvelope envelope
    ) {
        Base64.Encoder encoder = Base64.getEncoder();

        VaultEnvelopeResponse envelopeResponse = toEnvelopeResponse(envelope);

        return new VaultDetailsResponse(
                vault.getVaultId(),
                encoder.encodeToString(vault.getNameCiphertext()),
                vault.getNameAeadParams(),
                vault.getVaultVersion(),
                vault.getCurrentVaultKeyVersion(),
                vault.getCreatedAt(),
                vault.getUpdatedAt(),
                membership.getRole(),
                membership.getStatus(),
                membership.getJoinedAt(),
                membership.getExpiresAt(),
                envelopeResponse
        );
    }

    public VaultEnvelopeResponse toEnvelopeResponse(VaultKeyEnvelope envelope) {
        Base64.Encoder encoder = Base64.getEncoder();

        return new VaultEnvelopeResponse(
                envelope.getVaultKeyVersion(),
                envelope.getRecipientEncryptionKeyVersion(),
                envelope.getEnvelopeVersion(),
                encoder.encodeToString(envelope.getEncryptedVaultKey()),
                envelope.getEnvelopeParams(),
                envelope.getCreatedAt()
        );
    }
}