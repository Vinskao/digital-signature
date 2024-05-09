package com.mli.signature.module.signature.service;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

@Service
public class KeyPairService {

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    public KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        return keyGen.generateKeyPair();
    }

    public void saveKeys(KeyPair keyPair, Path privateKeyPath, Path publicKeyPath) throws Exception {
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        Files.write(privateKeyPath, privateKey.getEncoded());
        Files.write(publicKeyPath, publicKey.getEncoded());

        logger.info("Keys saved to {} and {}", privateKeyPath.toString(), publicKeyPath.toString());
    }
}