package ru.dmitrysvirgunov.passwordmanager.auth.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import ru.dmitrysvirgunov.passwordmanager.auth.entity.UserKeyMaterial;

import java.util.UUID;

public interface UserKeyMaterialRepository extends JpaRepository<UserKeyMaterial, UUID> {
}
