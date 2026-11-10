"""Owner-supplied service authentication; protocol safety settings are not overridable."""


def elasticsearch_options(settings):
    options = {"request_timeout": 5, "max_retries": 0}
    for field, option in (
        ("elasticsearch_ca_file", "ca_certs"),
        ("elasticsearch_client_cert", "client_cert"),
        ("elasticsearch_client_key", "client_key"),
    ):
        value = getattr(settings, field, None)
        if value:
            options[option] = str(value)
    api_key = getattr(settings, "elasticsearch_api_key", None)
    if api_key:
        options["api_key"] = api_key.get_secret_value()
    return options


def kafka_options(settings):
    options = {
        "bootstrap.servers": settings.kafka_bootstrap,
        "security.protocol": getattr(settings, "kafka_security_protocol", "PLAINTEXT"),
    }
    for field, option in (
        ("kafka_ca_file", "ssl.ca.location"),
        ("kafka_client_cert", "ssl.certificate.location"),
        ("kafka_client_key", "ssl.key.location"),
        ("kafka_sasl_mechanism", "sasl.mechanism"),
        ("kafka_sasl_username", "sasl.username"),
    ):
        value = getattr(settings, field, None)
        if value:
            options[option] = str(value)
    for field, option in (
        ("kafka_key_password", "ssl.key.password"),
        ("kafka_sasl_password", "sasl.password"),
    ):
        value = getattr(settings, field, None)
        if value:
            options[option] = value.get_secret_value()
    return options
