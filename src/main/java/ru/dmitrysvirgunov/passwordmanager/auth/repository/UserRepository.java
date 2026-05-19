package ru.dmitrysvirgunov.passwordmanager.auth.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import ru.dmitrysvirgunov.passwordmanager.auth.entity.User;
import ru.dmitrysvirgunov.passwordmanager.auth.model.UserStatus;

import java.util.Optional;
import java.util.UUID;

public interface UserRepository extends JpaRepository<User, UUID> {
    Optional<User> findByEmailIgnoreCase(String email);
    boolean existsByEmailIgnoreCase(String email);
    Optional<User> findByEmailIgnoreCaseAndStatus(String email, UserStatus status);
    Optional<User> findByEmailIgnoreCaseAndStatusNot(String email, UserStatus status);
    boolean existsByEmailIgnoreCaseAndStatusNot(String email, UserStatus status);
}
