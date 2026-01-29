import datetime as dt
import ipaddress
import os
from pathlib import Path

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
except Exception:  # pragma: no cover - handled at runtime
    x509 = None


class CertManager:
    def __init__(self, base_dir=None):
        base = Path(base_dir) if base_dir else Path.home() / ".cybernatu" / "ca"
        self.base_dir = base
        self.certs_dir = base / "certs"
        self.ca_key_path = base / "ca_key.pem"
        self.ca_cert_path = base / "ca_cert.pem"

    def ensure_ca(self):
        if self.ca_key_path.exists() and self.ca_cert_path.exists():
            return
        if x509 is None:
            raise RuntimeError("Falta 'cryptography' para generar certificados.")
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.certs_dir.mkdir(parents=True, exist_ok=True)

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CyberNatu"),
                x509.NameAttribute(NameOID.COMMON_NAME, "CyberNatu Local CA"),
            ]
        )
        now = dt.datetime.utcnow()
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    key_cert_sign=True,
                    key_agreement=False,
                    content_commitment=False,
                    data_encipherment=False,
                    encipher_only=False,
                    decipher_only=False,
                    crl_sign=True,
                ),
                critical=True,
            )
            .sign(key, hashes.SHA256())
        )

        self.ca_key_path.write_bytes(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        self.ca_cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    def get_ca_cert_path(self):
        self.ensure_ca()
        return str(self.ca_cert_path)

    def get_cert_for_host(self, host: str):
        self.ensure_ca()
        safe = host.replace(":", "_").replace("*", "_")
        cert_path = self.certs_dir / f"{safe}.pem"
        key_path = self.certs_dir / f"{safe}_key.pem"
        if cert_path.exists() and key_path.exists():
            return str(cert_path), str(key_path)
        if x509 is None:
            raise RuntimeError("Falta 'cryptography' para generar certificados.")

        ca_key = serialization.load_pem_private_key(self.ca_key_path.read_bytes(), password=None)
        ca_cert = x509.load_pem_x509_certificate(self.ca_cert_path.read_bytes())

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CyberNatu"),
                x509.NameAttribute(NameOID.COMMON_NAME, host),
            ]
        )
        now = dt.datetime.utcnow()
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=825))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        )

        sans = []
        try:
            ip = ipaddress.ip_address(host)
            sans.append(x509.IPAddress(ip))
        except Exception:
            sans.append(x509.DNSName(host))
        builder = builder.add_extension(x509.SubjectAlternativeName(sans), critical=False)
        cert = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())

        key_path.write_bytes(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        return str(cert_path), str(key_path)
