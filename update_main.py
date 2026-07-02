import re

with open('src/api/main.py', 'r') as f:
    content = f.read()

new_process_all = '''@app.post("/api/process")
@limiter.limit("30/minute")
def process_all(request: Request, payload: TextInput):
    text = payload.text
    key  = payload.key or ""

    # Validate sizes before any processing
    if len(text) > 1000:
        raise HTTPException(status_code=400, detail="Payload exceeds the maximum allowed length of 1000 characters.")
    if len(key) > 256:
        raise HTTPException(status_code=400, detail="Secret key exceeds the maximum allowed length of 256 characters.")

    adv = payload.advanced or AdvancedOptions()

    if adv.aes_aad and len(adv.aes_aad) > 256:
        raise HTTPException(status_code=400, detail="AAD exceeds the maximum allowed length of 256 characters.")

    cat = payload.category
    meth = payload.method
    
    res = {}

    # Hashing
    if cat in ("all", "hashing") or meth in ("MD5", "SHA-256", "SHA-512", "bcrypt"):
        h_res = {}
        if meth in ("all", "MD5"): h_res["MD5"] = hashing.hash_md5(text)
        if meth in ("all", "SHA-256"): h_res["SHA-256"] = hashing.hash_sha256(text)
        if meth in ("all", "SHA-512"): h_res["SHA-512"] = hashing.hash_sha512(text)
        if meth in ("all", "bcrypt"): h_res["bcrypt"] = hashing.hash_bcrypt(text) if text else "Awaiting input..."
        if h_res: res["hashing"] = h_res

    # Encoding
    if cat in ("all", "encoding") or meth in ("Base64", "URL", "Hex", "Binary", "Morse"):
        e_res = {}
        if meth in ("all", "Base64"): e_res["Base64"] = {"Encode": encoding.encode_base64(text), "Decode": encoding.decode_base64(text)}
        if meth in ("all", "URL"): e_res["URL"] = {"Encode": encoding.encode_url(text), "Decode": encoding.decode_url(text)}
        if meth in ("all", "Hex"): e_res["Hex"] = {"Encode": encoding.encode_hex(text), "Decode": encoding.decode_hex(text)}
        if meth in ("all", "Binary"): e_res["Binary"] = {"Encode": encoding.encode_binary(text), "Decode": encoding.decode_binary(text)}
        if meth in ("all", "Morse"): e_res["Morse"] = {"Encode": encoding.encode_morse(text), "Decode": encoding.decode_morse(text)}
        if e_res: res["encoding"] = e_res

    # Encryption
    if cat in ("all", "encryption") or meth in ("AES-256", "3DES", "ROT13", "XOR"):
        enc_res = {}
        if meth in ("all", "AES-256"):
            enc_res["AES-256"] = {
                "Encrypt": encryption.encrypt_aes(text, key, adv.aes_key_bits, adv.aes_aad, adv.aes_output_format),
                "Decrypt": encryption.decrypt_aes(text, key, adv.aes_key_bits, adv.aes_aad, adv.aes_output_format),
            }
        if meth in ("all", "3DES"):
            enc_res["3DES"] = {
                "Encrypt": encryption.encrypt_3des(text, key, adv.des_output_format),
                "Decrypt": encryption.decrypt_3des(text, key, adv.des_output_format),
            }
        if meth in ("all", "ROT13"):
            enc_res["ROT13"] = encryption.rot13(text)
        if meth in ("all", "XOR"):
            enc_res["XOR"] = {
                "Encrypt": encryption.xor_cipher(text, key, adv.xor_output_format),
                "Decrypt": encryption.xor_decipher(text, key, adv.xor_output_format),
            }
        if enc_res: res["encryption"] = enc_res

    # Formatting
    if cat in ("all", "formatting") or meth in ("JSON", "JWT Decoder"):
        f_res = {}
        if meth in ("all", "JSON"):
            f_res["JSON"] = {"Beautify": formatting.format_json_beautify(text), "Minify": formatting.format_json_minify(text)}
        if meth in ("all", "JWT Decoder"):
            f_res["JWT Decoder"] = formatting.decode_jwt(text)
        if f_res: res["formatting"] = f_res

    return res'''

pattern = re.compile(r'@app\.post\("/api/process"\).*?return {\n.*?\n    }', re.DOTALL)
content = pattern.sub(new_process_all, content)

with open('src/api/main.py', 'w') as f:
    f.write(content)
