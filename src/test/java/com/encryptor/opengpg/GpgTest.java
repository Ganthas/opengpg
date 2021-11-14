package com.encryptor.opengpg;

import org.junit.jupiter.api.Test;

class GpgTest {

    String recipient = "your recipient";
    String publicKey = "your secret key";
    String privateKey = "your secret key";
    String senderPassphrase = "your Passphrase";
    String inputFilePath = "/path/to/file/file.csv";
    String encryptedFilePath = inputFilePath + ".gpg";

    @Test
    void testEncryptFile() {
        ArmoredKeyPair armoredKeyPair = ArmoredKeyPair.of(privateKey, publicKey);
        Gpg.encryptFile(recipient,
                inputFilePath,
                encryptedFilePath,
                senderPassphrase,
                armoredKeyPair);
    }
}