package ru.dmitrysvirgunov.passwordmanager.vault.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import ru.dmitrysvirgunov.passwordmanager.vault.entity.VaultMember;
import ru.dmitrysvirgunov.passwordmanager.vault.entity.VaultMemberId;
import ru.dmitrysvirgunov.passwordmanager.vault.model.VaultMemberRole;
import ru.dmitrysvirgunov.passwordmanager.vault.model.VaultMemberStatus;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;

public interface VaultMemberRepository extends JpaRepository<VaultMember, VaultMemberId> {

    @Query(
            value = """
            select m
            from VaultMember m
            join Vault v on v.vaultId = m.id.vaultId
            where m.id.userId = :userId
              and m.status = :status
              and m.revokedAt is null
              and (m.expiresAt is null or m.expiresAt > :now)
            order by v.updatedAt desc, v.vaultId asc
            """,
            countQuery = """
            select count(m)
            from VaultMember m
            where m.id.userId = :userId
              and m.status = :status
              and m.revokedAt is null
              and (m.expiresAt is null or m.expiresAt > :now)
            """
    )
    Page<VaultMember> findReadableMemberships(
            @Param("userId") UUID userId,
            @Param("status") VaultMemberStatus status,
            @Param("now") OffsetDateTime now,
            Pageable pageable
    );

    @Query("""
            select count(m)
            from VaultMember m
            where m.id.userId = :userId
              and m.status = :status
              and m.role = :role
              and m.revokedAt is null
              and (m.expiresAt is null or m.expiresAt > :now)
            """)
    long countReadableMembershipsByRole(
            @Param("userId") UUID userId,
            @Param("status") VaultMemberStatus status,
            @Param("role") VaultMemberRole role,
            @Param("now") OffsetDateTime now
    );

    List<VaultMember> findByIdVaultIdOrderByJoinedAtAsc(UUID vaultId);

    @Query("""
            select count(m)
            from VaultMember m
            where m.id.userId = :userId
              and m.role = :role
              and m.status = :status
              and m.revokedAt is null
              and (m.expiresAt is null or m.expiresAt > :now)
            """)
    long countByUserIdAndRoleAndStatusAndReadableAt(
            @Param("userId") UUID userId,
            @Param("role") VaultMemberRole role,
            @Param("status") VaultMemberStatus status,
            @Param("now") OffsetDateTime now
    );

    @Query("""
            select m
            from VaultMember m
            where m.id.userId = :userId
              and m.role = :role
              and m.status = :status
              and m.revokedAt is null
              and (m.expiresAt is null or m.expiresAt > :now)
            order by m.id.vaultId asc
            """)
    List<VaultMember> findByUserIdAndRoleAndStatusAndReadableAt(
            @Param("userId") UUID userId,
            @Param("role") VaultMemberRole role,
            @Param("status") VaultMemberStatus status,
            @Param("now") OffsetDateTime now
    );

    @Query("""
            select m
            from VaultMember m
            where m.id.userId = :userId
              and m.status in :statuses
              and m.revokedAt is null
              and (m.expiresAt is null or m.expiresAt > :now)
            order by m.id.vaultId asc
            """)
    List<VaultMember> findByUserIdAndStatusesReadableAt(
            @Param("userId") UUID userId,
            @Param("statuses") List<VaultMemberStatus> statuses,
            @Param("now") OffsetDateTime now
    );

    boolean existsById(VaultMemberId id);

    List<VaultMember> findByIdVaultIdAndStatusAndRevokedAtIsNullOrderByJoinedAtAsc(
            UUID vaultId,
            VaultMemberStatus status
    );
}
