# cosmos-import-hexkey

*Tool to import a secp256k1 private key into the cosmos-sdk binary's keystore*

The binary has the ability to export an unarmored hex key by using `gaiad keys export <keyname> --unsafe --unarmoured-hex`. However, to import a key you can only do it by a nmominic, or by a previously exported armored and encrypted file. There is no way to import a private key in an unarmoured hex string.  

This tool will encrypt, and armors a hex key file.

Usage:  
`import-key.py <private-key in hex format> <name of key> [cosmos_binary]`

Two files will be created  
`<name of key>.pem` holds the armored private key    
`<name of key>.pwd` holds the passwor to the key  

You can import the key using:    
`gaiad keys import name_of_key name_of_key.pem < name_of_key.pwd`
