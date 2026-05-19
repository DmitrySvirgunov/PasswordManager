package ru.dmitrysvirgunov.passwordmanager.vault.model;

import ru.dmitrysvirgunov.passwordmanager.common.model.AeadParams;
import tools.jackson.databind.JsonNode;

import java.util.List;

public record DeleteVaultObjectInput(
        int expectedVersion,
        byte[] ciphertext,
        AeadParams contentAeadParams,
        byte[] wrappedRecordKey,
        JsonNode recordKeyWrapParams,
        byte[] encryptedPackageHash,
        byte[] clientSignature,
        int signatureFormatVersion,
        int signatureKeyVersion,
        List<BlobReferenceInput> blobReferences
) {
}
