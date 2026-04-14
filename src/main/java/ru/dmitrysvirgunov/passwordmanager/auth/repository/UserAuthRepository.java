package ru.dmitrysvirgunov.passwordmanager.auth.repository;

import ru.dmitrysvirgunov.passwordmanager.auth.entity.UserAuth;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface UserAuthRepository extends JpaRepository<UserAuth, UUID> {}
