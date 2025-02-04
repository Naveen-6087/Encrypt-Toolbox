from flask import Flask, request, render_template, redirect, url_for
from encryption import generate_aes_key, aes_encrypt, aes_decrypt, generate_rsa_keys, rsa_encrypt, rsa_decrypt, sha256_hash
import base64

app = Flask(__name__)

# Global variables to store keys
aes_key = None
private_key = None
public_key = None
weew
@app.route('/')
def index():
    return render_template('index.html', aes_key=aes_key, public_key=public_key)

@app.route('/generate_aes_key', methods=['POST'])
def generate_key():
    global aes_key
    aes_key = generate_aes_key()
    return redirect(url_for('index'))

@app.route('/aes_encrypt', methods=['POST'])
def encrypt_aes():
    global aes_key
    plaintext = request.form['plaintext']
    if aes_key:
        ciphertext = aes_encrypt(aes_key, plaintext)
        return render_template('index.html', ciphertext=ciphertext, aes_key=aes_key)
    return redirect(url_for('index'))

@app.route('/aes_decrypt', methods=['POST'])
def decrypt_aes():
    global aes_key
    ciphertext = request.form['ciphertext']
    if aes_key:
        plaintext = aes_decrypt(aes_key, ciphertext)
        return render_template('index.html', plaintext=plaintext, aes_key=aes_key)
    return redirect(url_for('index'))

@app.route('/generate_rsa_keys', methods=['POST'])
def generate_rsa():
    global private_key, public_key
    private_key, public_key = generate_rsa_keys()
    return redirect(url_for('index'))

@app.route('/rsa_encrypt', methods=['POST'])
def encrypt_rsa():
    global public_key
    plaintext = request.form['plaintext']
    if public_key:
        ciphertext = rsa_encrypt(public_key, plaintext)
        return render_template('index.html', rsa_ciphertext=ciphertext, public_key=public_key)
    return redirect(url_for('index'))

@app.route('/rsa_decrypt', methods=['POST'])
def decrypt_rsa():
    global private_key
    ciphertext = request.form['ciphertext']
    if private_key:
        plaintext = rsa_decrypt(private_key, ciphertext)
        return render_template('index.html', rsa_plaintext=plaintext, public_key=public_key)
    return redirect(url_for('index'))

@app.route('/sha256', methods=['POST'])
def hash_sha256():
    plaintext = request.form['plaintext']
    hashed_value = sha256_hash(plaintext)
    return render_template('index.html', sha_hash=hashed_value)

if __name__ == '__main__':
    app.run(debug=True)
