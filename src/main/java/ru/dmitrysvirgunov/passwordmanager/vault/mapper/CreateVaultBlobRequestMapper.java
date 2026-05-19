package ru.dmitrysvirgunov.passwordmanager.vault.mapper;

import org.mapstruct.Mapper;
import org.mapstruct.ReportingPolicy;
import ru.dmitrysvirgunov.passwordmanager.vault.dto.request.CreateVaultBlobRequest;
import ru.dmitrysvirgunov.passwordmanager.vault.model.CreateVaultBlobInput;

@Mapper(
        componentModel = "spring",
        unmappedTargetPolicy = ReportingPolicy.ERROR
)
public interface CreateVaultBlobRequestMapper {

    CreateVaultBlobInput toInput(CreateVaultBlobRequest request);
}
