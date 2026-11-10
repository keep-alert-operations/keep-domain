import base64
from pathlib import Path
from typing import Literal
from uuid import UUID
from urllib.parse import urlsplit

from pydantic import SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from keep.shared.crypto import EnvelopeCipher


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="KEEP_", extra="forbid")
    environment: Literal["development", "staging", "production"] = "development"
    database_url: SecretStr | None = None
    wrapping_key: SecretStr | None = None
    wrapping_keyring: Path | None = None
    wrapping_key_id: str = "local-1"
    deployment_epoch: str
    public_origin: str = "https://localhost:3443"
    pool_size: int = 4
    role: str = "product-api"
    capacity_profile: Path | None = None
    oidc_issuer: str | None = None
    oidc_client_id: str = "keep-web"
    oidc_client_secret: SecretStr | None = None
    superadmin_group: str | None = None
    directory_config: Path | None = None
    directory_search_profile: Path | None = None
    oidc_directory_source: str | None = None
    oidc_directory_id_claim: str | None = None
    oidc_directory_scope: str | None = None
    oidc_required_acr: str | None = None
    oidc_required_amr: tuple[str, ...] = ()
    oidc_ca_file: str | None = None
    elasticsearch_url: str | None = None
    elasticsearch_index: str = "keep-development-alerts"
    elasticsearch_api_key: SecretStr | None = None
    elasticsearch_ca_file: Path | None = None
    elasticsearch_client_cert: Path | None = None
    elasticsearch_client_key: Path | None = None
    redis_url: SecretStr | None = None
    kafka_bootstrap: str | None = None
    global_tenant_id: UUID | None = None
    kafka_admission_enabled: bool = False
    # Timed alert dismissal (REV-49) stays off until every writer runs this release.
    alert_dismissal_enabled: bool = False
    clock_health_file: Path | None = None
    database_clock_health_file: Path | None = None
    kafka_security_protocol: Literal["PLAINTEXT", "SSL", "SASL_SSL"] = "PLAINTEXT"
    kafka_ca_file: Path | None = None
    kafka_client_cert: Path | None = None
    kafka_client_key: Path | None = None
    kafka_key_password: SecretStr | None = None
    kafka_sasl_mechanism: Literal["PLAIN", "SCRAM-SHA-256", "SCRAM-SHA-512"] | None = None
    kafka_sasl_username: str | None = None
    kafka_sasl_password: SecretStr | None = None
    operator_binding: Path | None = None
    operator_database_url: SecretStr | None = None
    operator_grafana_token: SecretStr | None = None
    operator_kong_token: SecretStr | None = None
    operator_probe_token: SecretStr | None = None
    recovery_binding: Path | None = None
    recovery_credential: SecretStr | None = None
    # REV-65: the ticket counting service address, a deployment secret mounted only
    # into the product API. It may carry an access key in its query string, so it is
    # never logged or returned. An absent, empty or invalid address means ServiceNow
    # ticket panels are not connected; the API checks it at startup.
    ticket_count_url: SecretStr | None = None
    # Optional CA bundle that alone verifies the counting service's TLS certificate.
    ticket_count_ca_file: str | None = None
    worker_health_path: Path | None = None

    @model_validator(mode="after")
    def validate_settings(self):
        ingress = self.role in ("ingestion-api", "private-ingestion")
        if ingress and (not self.kafka_bootstrap or not self.global_tenant_id):
            raise ValueError("Ingress requires Kafka and the immutable Global tenant ID")
        if not ingress and not self.database_url:
            raise ValueError("This workload requires PostgreSQL")
        if self.directory_search_profile and not self.directory_config:
            raise ValueError("Directory search requires the explicit LDAP configuration")
        if not self.public_origin.startswith("https://"):
            raise ValueError("The browser origin must use HTTPS")
        if not 1 <= self.pool_size <= 32:
            raise ValueError("A bounded pool allocation is required")
        if not ingress and bool(self.wrapping_key) == bool(self.wrapping_keyring):
            raise ValueError("Supply exactly one wrapping key or mounted wrapping keyring")
        if (
            self.wrapping_key
            and len(base64.b64decode(self.wrapping_key.get_secret_value(), validate=True)) != 32
        ):
            raise ValueError("Wrapping key must be base64 of 32 bytes")
        if self.wrapping_key or self.wrapping_keyring:
            self.cipher()
        for certificate, key in (
            (self.elasticsearch_client_cert, self.elasticsearch_client_key),
            (self.kafka_client_cert, self.kafka_client_key),
        ):
            if bool(certificate) != bool(key):
                raise ValueError("Client certificate and key must be supplied together")
        if self.elasticsearch_url:
            parsed = urlsplit(self.elasticsearch_url)
            if (
                parsed.scheme not in ("http", "https")
                or not parsed.hostname
                or parsed.username
                or parsed.password
                or parsed.query
                or parsed.fragment
            ):
                raise ValueError(
                    "Elasticsearch requires an explicit origin without embedded secrets"
                )
            if parsed.scheme != "https" and (
                self.environment != "development"
                or self.elasticsearch_api_key
                or self.elasticsearch_client_cert
                or self.elasticsearch_ca_file
            ):
                raise ValueError(
                    "Elasticsearch credentials and nondevelopment bindings require HTTPS"
                )
        sasl = (self.kafka_sasl_mechanism, self.kafka_sasl_username, self.kafka_sasl_password)
        if self.kafka_security_protocol == "SASL_SSL":
            if not all(sasl):
                raise ValueError("SASL_SSL requires mechanism, username and password")
        elif any(sasl):
            raise ValueError("SASL credentials require SASL_SSL")
        if self.kafka_security_protocol == "PLAINTEXT" and (
            (self.kafka_bootstrap and self.environment != "development")
            or self.kafka_client_cert
            or self.kafka_ca_file
            or self.kafka_key_password
        ):
            raise ValueError(
                "Kafka plaintext is limited to isolated development without credentials"
            )
        return self

    def cipher(self):
        if self.wrapping_keyring:
            try:
                with self.wrapping_keyring.open("rb") as source:
                    document = source.read(65537)
                if len(document) > 65536:
                    raise ValueError()
                return EnvelopeCipher.from_keyring(document)
            except (OSError, ValueError, TypeError):
                raise ValueError("Invalid mounted wrapping keyring") from None
        return EnvelopeCipher(
            {self.wrapping_key_id: base64.b64decode(self.wrapping_key.get_secret_value())},
            self.wrapping_key_id,
        )
