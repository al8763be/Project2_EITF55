import os
import subprocess
import stat

# Directories for CA, Server, and Client
BASE_DIR = os.path.abspath("pki_setup")
CA_DIR = os.path.join(BASE_DIR, "ca")
SERVER_DIR = os.path.join(BASE_DIR, "server")
CLIENT_DIR = os.path.join(BASE_DIR, "client")

# Create directories
os.makedirs(CA_DIR, exist_ok=True)
os.makedirs(SERVER_DIR, exist_ok=True)
os.makedirs(CLIENT_DIR, exist_ok=True)

EXT_FILE = "/home/berni/Github/Project2_EITF55/PKI/rootCA.ext"

def generate_root_ca():
    # Generate the RSA key
    subprocess.run(["openssl", "genrsa", "-aes128", "-out", os.path.join(CA_DIR, "rootCA.key"), "2048"], check=True)

    # Create the CSR (Certificate Signing Request)
    subprocess.run([
        "openssl", "req", "-new", "-key", os.path.join(CA_DIR, "rootCA.key"),
        "-out", os.path.join(CA_DIR, "rootCA.csr"),
        "-subj", "/C=SE/ST=Scania/L=Lund/O=LU/OU=Education/CN=Demo CA/emailAddress=ca@demoland.se"
    ], check=True)

    # Create an extension file
    EXT_FILE = os.path.join(CA_DIR, "rootCA.ext")
    with open(EXT_FILE, "w") as f:
        f.write("""
        basicConstraints = critical,CA:TRUE
        keyUsage = critical, digitalSignature, keyCertSign, cRLSign
        subjectKeyIdentifier = hash
        """)

    # Sign the CSR to create the certificate using openssl x509
    subprocess.run([
        "openssl", "x509", "-req", "-in", os.path.join(CA_DIR, "rootCA.csr"),
        "-signkey", os.path.join(CA_DIR, "rootCA.key"),
        "-days", "3650",
        "-out", os.path.join(CA_DIR, "rootCA.pem"),
        "-extfile", EXT_FILE,
        "-sha256"
    ], check=True)

    print("Root CA created successfully!")


# Generate Server Key and CSR
def generate_server_cert():
    subprocess.run([
        "openssl", "genpkey", "-aes128", "-algorithm", "RSA", "-out", os.path.join(SERVER_DIR, "server_key.pem"), "-pkeyopt", "rsa_keygen_bits:2048"
    ], check=True)
    subprocess.run([
        "openssl", "req", "-new", "-key", os.path.join(SERVER_DIR, "server_key.pem"), "-out", os.path.join(SERVER_DIR, "server_csr.pem"),
        "-subj", "/C=SE/ST=Scania/L=Lund/O=LU/OU=Education/CN=server.demoland.se/emailAddress=server@demoland.se"
    ], check=True)

    # Create extension file
    with open(os.path.join(SERVER_DIR, "server_v3.txt"), "w") as f:
        f.write("""
        authorityKeyIdentifier=keyid,issuer
        basicConstraints=CA:FALSE
        keyUsage = keyAgreement, keyEncipherment, digitalSignature
        subjectAltName = @alt_names
        [alt_names]
        DNS.1 = localhost
        """)

    subprocess.run([
        "openssl", "x509", "-req", "-CA", os.path.join(CA_DIR, "rootCA.pem"), "-CAkey", os.path.join(CA_DIR, "rootCA.key"), "-in",
        os.path.join(SERVER_DIR, "server_csr.pem"), "-out", os.path.join(SERVER_DIR, "server_cert.pem"), "-days", "365", "-extfile", os.path.join(SERVER_DIR, "server_v3.txt"), "-set_serial", "1"
    ], check=True)

    subprocess.run([
        "openssl", "pkcs12", "-export", "-out", os.path.join(SERVER_DIR, "server.p12"), "-inkey", os.path.join(SERVER_DIR, "server_key.pem"), "-in", os.path.join(SERVER_DIR, "server_cert.pem"), "-certfile", os.path.join(CA_DIR, "rootCA.pem")
    ], check=True)

# Generate Client Key and CSR
def generate_client_cert():
    subprocess.run([
        "openssl", "genpkey", "-aes128", "-algorithm", "RSA", "-out", os.path.join(CLIENT_DIR, "client_key.pem"), "-pkeyopt", "rsa_keygen_bits:2048"
    ], check=True)
    subprocess.run([
        "openssl", "req", "-new", "-key", os.path.join(CLIENT_DIR, "client_key.pem"), "-out", os.path.join(CLIENT_DIR, "client_csr.pem"),
        "-subj", "/C=SE/ST=Scania/L=Lund/O=LU/OU=Education/CN=client.demoland.se/emailAddress=client@demoland.se"
    ], check=True)

    # Create extension file
    with open(os.path.join(CLIENT_DIR, "client_v3.txt"), "w") as f:
        f.write("""
        authorityKeyIdentifier=keyid,issuer
        basicConstraints=CA:FALSE
        keyUsage = digitalSignature, nonRepudiation, dataEncipherment
        subjectAltName = @alt_names
        [alt_names]
        DNS.1 = localhost
        """)

    # Sign client certificate with the CA
    subprocess.run([
        "openssl", "x509", "-req", "-CA", os.path.join(CA_DIR, "rootCA.pem"), "-CAkey", os.path.join(CA_DIR, "rootCA.key"), "-in",
        os.path.join(CLIENT_DIR, "client_csr.pem"), "-out", os.path.join(CLIENT_DIR, "client_cert.pem"), "-days", "365", "-extfile", os.path.join(CLIENT_DIR, "client_v3.txt"), "-set_serial", "2"
    ], check=True)

    # ✅ Create client.p12 file (missing step)
    subprocess.run([
        "openssl", "pkcs12", "-export", "-out", os.path.join(CLIENT_DIR, "client.p12"),
        "-inkey", os.path.join(CLIENT_DIR, "client_key.pem"),
        "-in", os.path.join(CLIENT_DIR, "client_cert.pem"),
        "-certfile", os.path.join(CA_DIR, "rootCA.pem")
    ], check=True)

    print("Client certificates and keys generated successfully!")

# Set Permissions
def set_permissions():
    os.chmod(CA_DIR, stat.S_IRWXU)
    os.chmod(SERVER_DIR, stat.S_IRWXU)
    os.chmod(CLIENT_DIR, stat.S_IRWXU)

    os.chmod(os.path.join(CA_DIR, "rootCA.key"), stat.S_IRUSR | stat.S_IWUSR)
    os.chmod(os.path.join(CA_DIR, "rootCA.pem"), stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)

    os.chmod(os.path.join(SERVER_DIR, "server_key.pem"), stat.S_IRUSR | stat.S_IWUSR)
    os.chmod(os.path.join(SERVER_DIR, "server_cert.pem"), stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)

    os.chmod(os.path.join(CLIENT_DIR, "client_key.pem"), stat.S_IRUSR | stat.S_IWUSR)
    os.chmod(os.path.join(CLIENT_DIR, "client_cert.pem"), stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)

if __name__ == "__main__":
    generate_root_ca()
    generate_server_cert()
    generate_client_cert()
    set_permissions()
    print("Certificates and keys generated successfully!")
