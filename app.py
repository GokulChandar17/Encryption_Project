from flask import Flask, render_template, request, jsonify
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import hashlib

app = Flask(__name__, static_url_path= '/static')

@app.route('/')
def index():
    # Determine which template to render based on the route
    # If the route is '/', render encryption.html
    # If the route is '/decrypt', render decryption.html
    route = request.path
    if route == '/':
        return render_template('encryption.html')
    elif route == '/decrypt':
        return render_template('decryption.html')
    else:
        return "Page not found ", 404 

@app.route('/encrypt', methods=['POST'])
def encrypt():
    encryption_technique = request.form['encryption_technique']
    plaintext = request.form.get('plaintext', '')  # Get plaintext from the form or set it to an empty string if not provided
    
    # Initialize ciphertext with a default value
    ciphertext = ""

    if encryption_technique == 'rsa':
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        ciphertext = public_key.encrypt(
            plaintext.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    elif encryption_technique == 'aes':
        key = b'Sixteen byte key'
        iv = b'Sixteen byte IV'
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    elif encryption_technique == 'des':
        key = b'Sixteen byte key'
        iv = b'Sixteen byte IV'
        cipher = Cipher(algorithms.TripleDES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    elif encryption_technique == 'sha256':
        hash_obj = hashlib.sha256()
        hash_obj.update(plaintext.encode())
        ciphertext = hash_obj.hexdigest()
    elif encryption_technique == 'sha512':
        hash_obj = hashlib.sha512()
        hash_obj.update(plaintext.encode())
        ciphertext = hash_obj.hexdigest()
    elif encryption_technique == 'md5':
        hash_obj = hashlib.md5()
        hash_obj.update(plaintext.encode())
        ciphertext = hash_obj.hexdigest()

    # Check if ciphertext is a string representing a hash value
    if isinstance(ciphertext, str):
        ciphertext = {'hash_value': ciphertext}
    elif isinstance(ciphertext, bytes):
        ciphertext = {'ciphertext': ciphertext.hex()}

    return jsonify(ciphertext)

@app.route('/decrypt', methods=['POST'])
def decrypt():
    decryption_technique = request.form['decryption_technique']
    ciphertext = request.form.get('ciphertext', '')  # Get ciphertext from the form or set it to an empty string if not provided

    # Initialize plaintext with a default value
    plaintext = ""

    if decryption_technique == 'rsa':
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        plaintext = private_key.decrypt(
            bytes.fromhex(ciphertext),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        ).decode()
    elif decryption_technique == 'aes':
        key = b'Sixteen byte key'
        iv = b'Sixteen byte IV'
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(bytes.fromhex(ciphertext)) + decryptor.finalize()
    elif decryption_technique == 'des':
        key = b'Sixteen byte key'
        iv = b'Sixteen byte IV'
        cipher = Cipher(algorithms.TripleDES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(bytes.fromhex(ciphertext)) + decryptor.finalize()
    elif decryption_technique == 'sha256' or decryption_technique == 'sha512' or decryption_technique == 'md5':
        plaintext = "Decryption not supported for hash functions."

    return jsonify({'plaintext': plaintext})

if __name__ == '__main__':
    app.run(debug=True)
