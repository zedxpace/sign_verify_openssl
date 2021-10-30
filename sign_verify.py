from OpenSSL.crypto import FILETYPE_PEM, TYPE_DSA, X509 ,dump_privatekey ,dump_publickey ,PKey, load_privatekey, load_publickey ,sign ,verify 
from hashlib import sha1
import sys 

public_key_file = "public_key"
private_key_file = "private_key"

##Generate DSA type Key
key = PKey()
key.generate_key(TYPE_DSA ,2048)

##store Private key in the file 
with open(private_key_file ,'w') as priv_key:
    priv_key.write(dump_privatekey(FILETYPE_PEM ,key).decode())

##store Public key in the file
with open(public_key_file ,"w") as pub_key:
    pub_key.write(dump_publickey(FILETYPE_PEM ,key).decode())


##Method to sign the message using the private key
def sign_msg(msg):
    msg = msg.encode('utf-8')
    msg = sha1(msg).hexdigest()
    
    with open(private_key_file ,'r') as signing_key:
        _key = signing_key.read()
    signing_key.close()
    _key = load_privatekey(FILETYPE_PEM ,_key)

    #return the signature
    signature = sign(_key ,msg ,'sha256')
    print("signature : " ,signature)
    return signature

##Method to verify the message using the public key corresponding to the private key
def verify_msg(msg ,signature):
    msg = msg.encode('utf-8')
    msg = sha1(msg).hexdigest()

    with open(public_key_file ,'r') as verifying_key:
        _key = verifying_key.read()
    verifying_key.close()
    _key = load_publickey(FILETYPE_PEM ,_key)

    x_509 = X509()
    x_509.set_pubkey(_key)

    ##if on verifying no exception is raised it means that verification is succeeded
    verify(x_509 ,signature ,msg ,'sha256')
    print("verification succeeds")

argument = sys.argv
print("starting to sign the message")
signature = sign_msg(argument[1])
print("starting to verify the message")
verify_msg(argument[1] ,signature)
print("Exiting")
