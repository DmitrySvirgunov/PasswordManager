package ru.dmitrysvirgunov.passwordmanager.audit.repository;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import ru.dmitrysvirgunov.passwordmanager.audit.entity.AuditEvent;
import ru.dmitrysvirgunov.passwordmanager.audit.model.AuditScopeType;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface AuditEventRepository extends JpaRepository<AuditEvent, Long> {

    Optional<AuditEvent> findTopByScopeTypeAndScopeIdOrderByEventIdDesc(
            AuditScopeType scopeType,
            UUID scopeId
    );

    List<AuditEvent> findByScopeTypeAndScopeIdOrderByEventIdAsc(
            AuditScopeType scopeType,
            UUID scopeId
    );

    Optional<AuditEvent> findTopByScopeTypeAndScopeIdAndEventIdLessThanOrderByEventIdDesc(
            AuditScopeType scopeType,
            UUID scopeId,
            Long eventId
    );

    Optional<AuditEvent> findByScopeTypeAndScopeIdAndEventId(
            AuditScopeType scopeType,
            UUID scopeId,
            Long eventId
    );

    @Query(
            value = """
                    select event
                    from AuditEvent event
                    where event.scopeType = :scopeType
                      and event.scopeId = :scopeId
                      and event.eventType = coalesce(:eventType, event.eventType)
                      and event.createdAt >= coalesce(:createdAfter, event.createdAt)
                    order by event.eventId desc
                    """,
            countQuery = """
                    select count(event)
                    from AuditEvent event
                    where event.scopeType = :scopeType
                      and event.scopeId = :scopeId
                      and event.eventType = coalesce(:eventType, event.eventType)
                      and event.createdAt >= coalesce(:createdAfter, event.createdAt)
                    """
    )
    Page<AuditEvent> findPageByScopeFilters(
            @Param("scopeType") AuditScopeType scopeType,
            @Param("scopeId") UUID scopeId,
            @Param("eventType") String eventType,
            @Param("createdAfter") OffsetDateTime createdAfter,
            Pageable pageable
    );

    @Query(
            value = """
                    select event.*
                    from audit_events event
                    left join users actor on actor.user_id = event.actor_user_id
                    where event.scope_type = cast(:scopeType as text)
                      and event.scope_id = :scopeId
                      and event.event_type = coalesce(:eventType, event.event_type)
                      and event.created_at >= coalesce(:createdAfter, event.created_at)
                      and (
                        :actorPattern is null
                        or lower(coalesce(actor.email, '')) like :actorPattern
                        or lower(coalesce(cast(event.actor_user_id as text), '')) like :actorPattern
                      )
                      and (
                        :affectedPattern is null
                        or exists (
                            select 1
                            from users target_user
                            where cast(target_user.user_id as text) in (
                                coalesce(event.meta ->> 'targetUserId', ''),
                                coalesce(event.meta ->> 'inviteeUserId', ''),
                                coalesce(event.meta ->> 'userId', '')
                            )
                              and lower(target_user.email) like :affectedPattern
                        )
                        or exists (
                            select 1
                            from vault_invites invite
                            where cast(invite.invite_id as text) = coalesce(event.meta ->> 'inviteId', '')
                              and lower(invite.invitee_email) like :affectedPattern
                        )
                        or lower(coalesce(event.meta ->> 'inviteeEmail', '')) like :affectedPattern
                        or lower(coalesce(event.meta ->> 'objectId', '')) like :affectedPattern
                        or lower(coalesce(event.meta ->> 'targetUserId', '')) like :affectedPattern
                        or lower(coalesce(event.meta ->> 'inviteeUserId', '')) like :affectedPattern
                        or lower(coalesce(event.meta ->> 'userId', '')) like :affectedPattern
                      )
                      and (
                        :queryPattern is null
                        or lower(event.event_type) like :queryPattern
                        or lower(coalesce(actor.email, '')) like :queryPattern
                        or exists (
                            select 1
                            from users target_user
                            where cast(target_user.user_id as text) in (
                                coalesce(event.meta ->> 'targetUserId', ''),
                                coalesce(event.meta ->> 'inviteeUserId', ''),
                                coalesce(event.meta ->> 'userId', '')
                            )
                              and lower(target_user.email) like :queryPattern
                        )
                        or exists (
                            select 1
                            from vault_invites invite
                            where cast(invite.invite_id as text) = coalesce(event.meta ->> 'inviteId', '')
                              and lower(invite.invitee_email) like :queryPattern
                        )
                        or lower(coalesce(event.meta ->> 'inviteeEmail', '')) like :queryPattern
                        or lower(coalesce(cast(event.meta as text), '')) like :queryPattern
                        or lower(case event.event_type
                            when 'AUTH.USER_REGISTERED' then 'аккаунт регистрация'
                            when 'AUTH.LOGIN_SUCCEEDED' then 'вход сессия'
                            when 'AUTH.REFRESH_SUCCEEDED' then 'обновление сессия токен'
                            when 'AUTH.LOGOUT_SUCCEEDED' then 'выход сессия'
                           when 'AUTH.PASSWORD_CHANGED' then 'пароль мастер-пароль'
                           when 'AUTH.KEYS_ROTATED' then 'ключи аккаунт перевыпуск'
                           when 'AUTH.ACCOUNT_DELETED' then 'удаление аккаунт'
                            when 'VAULT.CREATED' then 'сейф создание'
                            when 'VAULT.KEY_ROTATED' then 'сейф ключ ротация'
                            when 'VAULT.OBJECT_CREATED' then 'запись создание'
                            when 'VAULT.OBJECT_UPDATED' then 'запись обновление'
                            when 'VAULT.OBJECT_DELETED' then 'запись удаление'
                            when 'VAULT.INVITE_CREATED' then 'приглашение доступ'
                            when 'VAULT.INVITE_REVOKED' then 'приглашение отзыв'
                            when 'VAULT.INVITE_ACCEPTED' then 'приглашение принято доступ'
                            when 'VAULT.INVITE_DECLINED' then 'приглашение отклонено'
                            when 'VAULT.MEMBER_ROLE_CHANGED' then 'роль участник доступ'
                            when 'VAULT.OWNERSHIP_TRANSFERRED' then 'владелец передача сейф'
                            when 'VAULT.DELETED' then 'сейф удаление'
                            when 'VAULT.MEMBER_REVOKED' then 'доступ отозван'
                            when 'RECORD_KEY_ROTATED' then 'запись ключ ротация'
                            else ''
                        end) like :queryPattern
                      )
                    order by event.event_id desc
                    """,
            countQuery = """
                    select count(*)
                    from audit_events event
                    left join users actor on actor.user_id = event.actor_user_id
                    where event.scope_type = cast(:scopeType as text)
                      and event.scope_id = :scopeId
                      and event.event_type = coalesce(:eventType, event.event_type)
                      and event.created_at >= coalesce(:createdAfter, event.created_at)
                      and (
                        :actorPattern is null
                        or lower(coalesce(actor.email, '')) like :actorPattern
                        or lower(coalesce(cast(event.actor_user_id as text), '')) like :actorPattern
                      )
                      and (
                        :affectedPattern is null
                        or exists (
                            select 1
                            from users target_user
                            where cast(target_user.user_id as text) in (
                                coalesce(event.meta ->> 'targetUserId', ''),
                                coalesce(event.meta ->> 'inviteeUserId', ''),
                                coalesce(event.meta ->> 'userId', '')
                            )
                              and lower(target_user.email) like :affectedPattern
                        )
                        or exists (
                            select 1
                            from vault_invites invite
                            where cast(invite.invite_id as text) = coalesce(event.meta ->> 'inviteId', '')
                              and lower(invite.invitee_email) like :affectedPattern
                        )
                        or lower(coalesce(event.meta ->> 'inviteeEmail', '')) like :affectedPattern
                        or lower(coalesce(event.meta ->> 'objectId', '')) like :affectedPattern
                        or lower(coalesce(event.meta ->> 'targetUserId', '')) like :affectedPattern
                        or lower(coalesce(event.meta ->> 'inviteeUserId', '')) like :affectedPattern
                        or lower(coalesce(event.meta ->> 'userId', '')) like :affectedPattern
                      )
                      and (
                        :queryPattern is null
                        or lower(event.event_type) like :queryPattern
                        or lower(coalesce(actor.email, '')) like :queryPattern
                        or exists (
                            select 1
                            from users target_user
                            where cast(target_user.user_id as text) in (
                                coalesce(event.meta ->> 'targetUserId', ''),
                                coalesce(event.meta ->> 'inviteeUserId', ''),
                                coalesce(event.meta ->> 'userId', '')
                            )
                              and lower(target_user.email) like :queryPattern
                        )
                        or exists (
                            select 1
                            from vault_invites invite
                            where cast(invite.invite_id as text) = coalesce(event.meta ->> 'inviteId', '')
                              and lower(invite.invitee_email) like :queryPattern
                        )
                        or lower(coalesce(event.meta ->> 'inviteeEmail', '')) like :queryPattern
                        or lower(coalesce(cast(event.meta as text), '')) like :queryPattern
                        or lower(case event.event_type
                            when 'AUTH.USER_REGISTERED' then 'аккаунт регистрация'
                            when 'AUTH.LOGIN_SUCCEEDED' then 'вход сессия'
                            when 'AUTH.REFRESH_SUCCEEDED' then 'обновление сессия токен'
                            when 'AUTH.LOGOUT_SUCCEEDED' then 'выход сессия'
                           when 'AUTH.PASSWORD_CHANGED' then 'пароль мастер-пароль'
                           when 'AUTH.KEYS_ROTATED' then 'ключи аккаунт перевыпуск'
                           when 'AUTH.ACCOUNT_DELETED' then 'удаление аккаунт'
                            when 'VAULT.CREATED' then 'сейф создание'
                            when 'VAULT.KEY_ROTATED' then 'сейф ключ ротация'
                            when 'VAULT.OBJECT_CREATED' then 'запись создание'
                            when 'VAULT.OBJECT_UPDATED' then 'запись обновление'
                            when 'VAULT.OBJECT_DELETED' then 'запись удаление'
                            when 'VAULT.INVITE_CREATED' then 'приглашение доступ'
                            when 'VAULT.INVITE_REVOKED' then 'приглашение отзыв'
                            when 'VAULT.INVITE_ACCEPTED' then 'приглашение принято доступ'
                            when 'VAULT.INVITE_DECLINED' then 'приглашение отклонено'
                            when 'VAULT.MEMBER_ROLE_CHANGED' then 'роль участник доступ'
                            when 'VAULT.OWNERSHIP_TRANSFERRED' then 'владелец передача сейф'
                            when 'VAULT.DELETED' then 'сейф удаление'
                            when 'VAULT.MEMBER_REVOKED' then 'доступ отозван'
                            when 'RECORD_KEY_ROTATED' then 'запись ключ ротация'
                            else ''
                        end) like :queryPattern
                      )
                    """,
            nativeQuery = true
    )
    Page<AuditEvent> searchPageByScopeFilters(
            @Param("scopeType") String scopeType,
            @Param("scopeId") UUID scopeId,
            @Param("eventType") String eventType,
            @Param("createdAfter") OffsetDateTime createdAfter,
            @Param("actorPattern") String actorPattern,
            @Param("affectedPattern") String affectedPattern,
            @Param("queryPattern") String queryPattern,
            Pageable pageable
    );

    @Query(
            value = """
                    select distinct event.event_type
                    from audit_events event
                    where event.scope_type = cast(:scopeType as text)
                      and event.scope_id = :scopeId
                      and event.created_at >= coalesce(:createdAfter, event.created_at)
                    order by event.event_type asc
                    """,
            nativeQuery = true
    )
    List<String> findDistinctEventTypesByScopeFilters(
            @Param("scopeType") String scopeType,
            @Param("scopeId") UUID scopeId,
            @Param("createdAfter") OffsetDateTime createdAfter
    );

    @Query("""
            select event
            from AuditEvent event
            where event.eventId in (
                select head.headEventId
                from AuditScopeHead head
                where not exists (
                    select 1
                    from AuditAnchorOutbox outbox
                    where outbox.sourceInstanceId = :sourceInstanceId
                      and outbox.scopeType = head.scopeType
                      and outbox.scopeId = head.scopeId
                      and outbox.eventId = head.headEventId
                )
            )
            order by event.eventId asc
            """)
    List<AuditEvent> findHeadEventsMissingAnchorOutbox(
            @Param("sourceInstanceId") String sourceInstanceId,
            Pageable pageable
    );
}
