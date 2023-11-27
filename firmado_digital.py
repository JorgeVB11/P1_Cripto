from OpenSSL import crypto


def sign_digitally(self, mensaje, private_key_path):
    private_key = self.get_pkey(private_key_path)
    return crypto.sign(private_key, mensaje, "sha256")

