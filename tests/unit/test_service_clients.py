import base64

import pytest
from pydantic import ValidationError

from appchi.config import Settings
from appchi.service_clients import elasticsearch_options, kafka_options


def settings(**values):
    return Settings(
        database_url="postgresql://unused",
        wrapping_key=base64.b64encode(b"x" * 32).decode(),
        deployment_epoch="fixture",
        **values,
    )


@pytest.mark.parametrize(
    "values",
    [
        {"elasticsearch_url": "http://localhost:9200", "elasticsearch_api_key": "secret"},
        {"environment": "staging", "elasticsearch_url": "http://localhost:9200"},
        {"elasticsearch_url": "https://user:secret@localhost:9200"},
        {"elasticsearch_client_cert": "certificate.pem"},
        {"kafka_bootstrap": "localhost:9092", "environment": "staging"},
        {"kafka_security_protocol": "SASL_SSL", "kafka_sasl_username": "user"},
        {"kafka_sasl_password": "secret"},
        {"kafka_client_cert": "certificate.pem", "kafka_client_key": "key.pem"},
    ],
)
def test_unsafe_or_incomplete_service_authentication_is_rejected(values):
    with pytest.raises(ValidationError):
        settings(**values)


def test_tls_settings_preserve_verification_and_mask_secrets():
    config = settings(
        elasticsearch_url="https://search.invalid",
        elasticsearch_api_key="es-secret",
        elasticsearch_ca_file="ca.pem",
        kafka_bootstrap="kafka.invalid:9093",
        kafka_security_protocol="SASL_SSL",
        kafka_sasl_mechanism="SCRAM-SHA-512",
        kafka_sasl_username="application",
        kafka_sasl_password="kafka-secret",
    )
    assert "es-secret" not in repr(config) and "kafka-secret" not in repr(config)
    assert elasticsearch_options(config)["api_key"] == "es-secret"
    assert "verify_certs" not in elasticsearch_options(config)
    assert kafka_options(config)["security.protocol"] == "SASL_SSL"
    assert kafka_options(config)["sasl.password"] == "kafka-secret"
    assert "enable.ssl.certificate.verification" not in kafka_options(config)
