from quantumshield import QuantumShield

qs = QuantumShield(parameter_set="512")
key_pair = qs.generate_keypair()
print(f"key_pair: {key_pair}, Type: {type(key_pair)}")
if isinstance(key_pair, tuple):
    public_key, private_key = key_pair
    print(f"Public Key: {public_key}")
    print(f"Private Key: {private_key}")
else:
    public_key = key_pair.public_key.to_pem()
    private_key = key_pair.private_key.to_pem()
    print(f"Public Key: {public_key}")
    print(f"Private Key: {private_key}")
