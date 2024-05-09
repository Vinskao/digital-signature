package com.mli.signature.module.signature.service;

import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * 服務層，提供生成密鑰庫的功能。
 * 
 * 使用 Bouncy Castle 提供的工具來生成密鑰對和自簽名證書，然後將其存儲到密鑰庫中。
 * 
 * @author D3031104
 * @version 1.0
 */
@Service
public class KeyStoreService {
    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    /**
     * 生成一個密鑰庫，包含一個自簽名的證書和相應的私鑰，然後將其保存到指定的位置。
     * 
     * @param keystorePath     保存密鑰庫的路徑
     * @param keystorePassword 密鑰庫的密碼
     * @param alias            將證書與私鑰關聯的別名
     * @param keySize          生成的 RSA 密鑰的大小（位）
     * @throws NoSuchAlgorithmException  如果指定的加密算法無效
     * @throws CertificateException      如果操作與證書有關，並且發生錯誤
     * @throws NoSuchProviderException   如果指定的提供程序不存在
     * @throws KeyStoreException         如果操作與密鑰庫有關，並且發生錯誤
     * @throws IOException               如果發生 I/O 錯誤
     * @throws OperatorCreationException 如果無法創建操作者
     */
    public void generateKeyStore(String keystorePath, String keystorePassword, String alias, int keySize)
            throws NoSuchAlgorithmException, CertificateException, NoSuchProviderException, KeyStoreException,
            IOException, OperatorCreationException {
        Security.addProvider(new BouncyCastleProvider());

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(keySize);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        long now = System.currentTimeMillis();
        Date startDate = new Date(now);

        X500Name dnName = new X500Name("CN=John Doe, OU=Java, O=Home, L=City, ST=State, C=US");
        BigInteger serialNumber = BigInteger.valueOf(now);
        Date endDate = new Date(now + 365 * 24 * 60 * 60 * 1000L); // Use valid period of one year

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                dnName, serialNumber, startDate, endDate, dnName, keyPair.getPublic());

        BasicConstraints basicConstraints = new BasicConstraints(true); // <-- true for CA, false for EndEntity
        certBuilder.addExtension(new ASN1ObjectIdentifier("2.5.29.19"), true, basicConstraints);

        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WithRSAEncryption")
                .build(keyPair.getPrivate());
        X509CertificateHolder certHolder = certBuilder.build(contentSigner);

        X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);

        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null, null); // Initialize the KeyStore
        keyStore.setKeyEntry(alias, keyPair.getPrivate(), keystorePassword.toCharArray(),
                new java.security.cert.Certificate[] { cert });

        try (FileOutputStream fos = new FileOutputStream(keystorePath)) {
            keyStore.store(fos, keystorePassword.toCharArray());
        }

        logger.info("Keystore generated successfully at {}", keystorePath);
    }
}