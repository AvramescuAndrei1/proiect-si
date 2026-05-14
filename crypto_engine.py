import os, time, psutil, subprocess, hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_pad
from cryptography.hazmat.primitives import serialization

class CryptoEngine:
    def get_mem(self):
        return psutil.Process().memory_info().rss / 1024

    def get_overhead(self, ossl_path):
        t1 = time.perf_counter()
        subprocess.run([ossl_path, "version"], capture_output=True)
        return (time.perf_counter() - t1) * 1000

    def aes_lib(self, data, key_str, path, op="enc"):
        t1 = time.perf_counter(); m1 = self.get_mem()
        key = hashlib.sha256(key_str.encode()).digest()
        if op == "enc":
            iv = os.urandom(16)
            padder = padding.PKCS7(128).padder()
            p_data = padder.update(data) + padder.finalize()
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
            res = iv + cipher.encryptor().update(p_data) + cipher.encryptor().finalize()
            out = path + ".lib.enc"
        else:
            iv, c_data = data[:16], data[16:]
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
            p_data = cipher.decryptor().update(c_data) + cipher.decryptor().finalize()
            unpadder = padding.PKCS7(128).unpadder()
            res = unpadder.update(p_data) + unpadder.finalize()
            out = path.replace(".enc", ".dec")
        with open(out, "wb") as f: f.write(res)
        return out, (time.perf_counter() - t1) * 1000, self.get_mem() - m1

    def aes_ossl(self, path, key_str, ossl_path, op="enc"):
        oh = self.get_overhead(ossl_path)
        t1 = time.perf_counter(); m1 = self.get_mem()
        out = path + ".ossl.enc" if op == "enc" else path.replace(".enc", ".dec")
        cmd = [ossl_path, "enc", "-aes-256-cbc", "-salt", "-in", path, "-out", out, "-pass", f"pass:{key_str}"]
        if op == "dec": cmd.insert(2, "-d")
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode != 0: raise Exception(f"Eroare OpenSSL: {res.stderr}")
        total_t = (time.perf_counter() - t1) * 1000
        pure_t = max(0.01, total_t - oh)
        return out, pure_t, self.get_mem() - m1

    def rsa_lib(self, data, path, op="enc"):
        t1 = time.perf_counter(); m1 = self.get_mem()
        k_path = "private.pem"
        try:
            if op == "enc":
                priv = rsa.generate_private_key(65537, 2048)
                with open(k_path, "wb") as f: f.write(priv.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption()))
                pub = priv.public_key()
                res = pub.encrypt(data, asym_pad.OAEP(mgf=asym_pad.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
                out = path + ".rsa.enc"
            else:
                with open(k_path, "rb") as f: priv = serialization.load_pem_private_key(f.read(), password=None)
                res = priv.decrypt(data, asym_pad.OAEP(mgf=asym_pad.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
                out = path.replace(".enc", ".dec")
            with open(out, "wb") as f: f.write(res)
            return out, (time.perf_counter() - t1) * 1000, self.get_mem() - m1
        except Exception as e: raise Exception(f"Eroare RSA Lib: {str(e)}")

    def rsa_ossl(self, path, ossl_path, op="enc"):
        oh = self.get_overhead(ossl_path)
        t1 = time.perf_counter(); m1 = self.get_mem()
        k = "rsa_key.pem"
        out = path + ".ossl.rsa" if op == "enc" else path.replace(".rsa", ".dec")
        if op == "enc":
            subprocess.run([ossl_path, "genpkey", "-algorithm", "RSA", "-out", k, "-pkeyopt", "rsa_keygen_bits:2048"], check=True)
            res = subprocess.run([ossl_path, "pkeyutl", "-encrypt", "-pubin", "-inkey", k, "-in", path, "-out", out], capture_output=True, text=True)
        else:
            res = subprocess.run([ossl_path, "pkeyutl", "-decrypt", "-inkey", k, "-in", path, "-out", out], capture_output=True, text=True)
        if res.returncode != 0: raise Exception(f"Eroare OpenSSL RSA: {res.stderr}")
        total_t = (time.perf_counter() - t1) * 1000
        pure_t = max(0.01, total_t - oh)
        return out, pure_t, self.get_mem() - m1