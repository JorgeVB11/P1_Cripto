from OpenSSL import crypto


def sign_digitally(self, mensaje, private_key_path):
    private_key = self.get_pkey(private_key_path)
    return crypto.sign(private_key, mensaje, "sha256")


def verify_sign(self, mensaje, sign, user_cert_address):
    try:
        user_cert = self.get_certificate(user_cert_address)
        crypto.verify(user_cert, sign, mensaje, "sha256")
        print("La firma es válida.\n")
        return True
    except crypto.Error:
        print(crypto.Error)
        print("La firma es inválida.\n")
        return False