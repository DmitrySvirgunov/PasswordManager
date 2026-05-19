package ru.dmitrysvirgunov.passwordmanager.vault.service;

import ru.dmitrysvirgunov.passwordmanager.common.model.AeadParams;
import ru.dmitrysvirgunov.passwordmanager.vault.model.BlobReferenceInput;
import tools.jackson.databind.JsonNode;

import java.util.List;

record VaultObjectSignaturePayload(
        byte[] ciphertext,
        AeadParams contentAeadParams,
        byte[] wrappedRecordKey,
        JsonNode recordKeyWrapParams,
        byte[] encryptedPackageHash,
        byte[] clientSignature,
        int signatureKeyVersion,
        int signatureFormatVersion,
        List<BlobReferenceInput> blobReferences
) {
}
