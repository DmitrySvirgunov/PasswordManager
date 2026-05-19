# PasswordManagerServer

Серверная часть менеджера паролей на `Spring Boot + PostgreSQL`.

Сервер предоставляет API для клиента `PasswordManagerClient` и отвечает за:
- аутентификацию и сессии;
- хранение зашифрованных сейфов и объектов;
- загрузку зашифрованных blob-файлов;
- совместный доступ к сейфам;
- аудит действий и проверку целостности журнала;
- синхронизацию изменений между участниками сейфа.

## Стек

- Java 24
- Spring Boot 4
- Spring Security
- Spring Data JPA
- PostgreSQL
- Liquibase
- Maven
- Testcontainers

## Ключевые модули API

- `/auth` — регистрация, вход, refresh/logout, профиль, смена пароля, перевыпуск ключей, удаление аккаунта
- `/vaults` — сейфы, записи, участники, инвайты, envelopes, sync
- `/vaults/{vaultId}/blobs` — загрузка и скачивание файлов
- `/audit` — события, проверка цепочки, проверка anchor/integrity

## Требования

- JDK 24
- Maven 3.9+
- PostgreSQL

## Обязательные переменные окружения

Минимально для запуска сервера нужны:

```env
SPRING_DATASOURCE_URL=jdbc:postgresql://localhost:5432/password_manager
SPRING_DATASOURCE_USERNAME=postgres
SPRING_DATASOURCE_PASSWORD=postgres

SECURITY_HASHING_HMAC_SECRET_BASE64=...
APP_SECURITY_JWT_SECRET_BASE64=...

APP_AUDIT_SIGNING_PRIVATE_KEY_PKCS8_BASE64=...
APP_AUDIT_SIGNING_PUBLIC_KEY_X509_BASE64=...
```

Дополнительно можно настроить:
- `SPRING_PROFILES_ACTIVE`
- `SERVER_PORT`
- `APP_MAIL_FROM`
- `APP_MAIL_VERIFY_BASE_URL`

## Запуск

Локальный запуск:

```bash
mvn spring-boot:run
```

По умолчанию сервер слушает `http://localhost:8080`.

## Миграции базы данных

Схема управляется через Liquibase:

- master changelog: `src/main/resources/db/changelog/changelog-master.xml`
- auth migrations: `src/main/resources/db/changelog/auth`
- vault and audit migrations: `src/main/resources/db/changelog/vault`

## Связанный клиент

Клиентская часть проекта оформляется отдельно как `PasswordManagerClient`.

Для локальной разработки удобно запускать:
- сервер на `http://localhost:8080`
- клиент на `https://localhost:5173` или через Vite dev server
