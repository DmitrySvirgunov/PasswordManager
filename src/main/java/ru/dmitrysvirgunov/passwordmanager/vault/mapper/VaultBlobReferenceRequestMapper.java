package ru.dmitrysvirgunov.passwordmanager.vault.mapper;

import org.mapstruct.Mapper;
import org.mapstruct.ReportingPolicy;
import ru.dmitrysvirgunov.passwordmanager.vault.dto.request.BlobReferenceRequest;
import ru.dmitrysvirgunov.passwordmanager.vault.model.BlobReferenceInput;

@Mapper(
        componentModel = "spring",
        unmappedTargetPolicy = ReportingPolicy.ERROR
)
public interface VaultBlobReferenceRequestMapper {

    BlobReferenceInput toInput(BlobReferenceRequest request);
}
