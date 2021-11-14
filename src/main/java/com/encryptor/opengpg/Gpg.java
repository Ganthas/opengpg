package com.encryptor.opengpg;


import name.neuhalfen.projects.crypto.bouncycastle.openpgp.BouncyGPG;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.KeyringConfigCallbacks;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.InMemoryKeyring;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfigs;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.util.io.Streams;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;

public class Gpg {
    public static void encryptFile(String recipient,
                                   String inputFilePath,
                                   String encryptedFilePath,
                                   String senderPassphrase,
                                   ArmoredKeyPair armoredKeyPair) {
        Security.addProvider(new BouncyCastleProvider());
        InMemoryKeyring keyringConfig = keyring(senderPassphrase, armoredKeyPair);

        try {
            final FileOutputStream fileOutput = new FileOutputStream(encryptedFilePath);
            final BufferedOutputStream bufferedOut = new BufferedOutputStream(fileOutput);

            final OutputStream outputStream = BouncyGPG
                    .encryptToStream()
                    .withConfig(keyringConfig)
                    .withStrongAlgorithms()
                    .toRecipient(recipient)
                    .andSignWith(recipient)
                    .binaryOutput()
                    .andWriteTo(bufferedOut);
            final FileInputStream is = new FileInputStream(inputFilePath);
            Streams.pipeAll(is, outputStream);

        } catch (PGPException
                | NoSuchAlgorithmException
                | IOException
                | SignatureException
                | NoSuchProviderException e) {
            e.printStackTrace();
        }
    }

    private static InMemoryKeyring keyring(String passphrase,
                                           ArmoredKeyPair armoredKeyPair) {
        InMemoryKeyring keyring = null;
        try {
            keyring =
                    KeyringConfigs.forGpgExportedKeys(KeyringConfigCallbacks.withPassword(passphrase));
            keyring.addSecretKey(armoredKeyPair.privateKey().getBytes(StandardCharsets.UTF_8));
            keyring.addPublicKey(armoredKeyPair.publicKey().getBytes(StandardCharsets.UTF_8));
        } catch (IOException | PGPException e) {
            e.printStackTrace();
        }

        return keyring;
    }
}