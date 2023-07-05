from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime

# Generate a new RSA key pair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

# Create a self-signed certificate
subject = issuer = x509.Name([
    x509.NameAttribute(x509.NameOID.COUNTRY_NAME, 'US'),
    x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, 'California'),
    x509.NameAttribute(x509.NameOID.LOCALITY_NAME, 'San Francisco'),
    x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, 'My Organization'),
    x509.NameAttribute(x509.NameOID.COMMON_NAME, 'example.com')
])
cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(private_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(datetime.datetime.utcnow()).not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365)).sign(private_key, hashes.SHA256(), default_backend())

# Save the private key to a .pem file
pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)
with open('private_key.pem', 'wb') as f:
    f.write(pem)

# Save the certificate to a .crt file
crt = cert.public_bytes(serialization.Encoding.PEM)
with open('certificate.crt', 'wb') as f:
    f.write(crt)

# Save the public key to a .pub file
pub = private_key.public_key().public_bytes(
    encoding=serialization.Encoding.OpenSSH,
    format=serialization.PublicFormat.OpenSSH
)
with open('public_key.pub', 'wb') as f:
    f.write(pub)
