package com.mli.signature.module.signature.utility;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestAlgorithmIdentifierFinder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * 數位簽章工具類，提供從密鑰庫加載私鑰和公鑰，以及使用私鑰簽名數據和驗證數據的方法。
 *
 * @author D3031104
 * @version 1.0
 */
@Component
public class DigitalSignatureUtils {
    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    /**
     * 私钥签名
     * 
     * @param key       私钥
     * @param algorithm 算法
     * @param in        输入数据
     * @return 签名
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws SignatureException
     */
    public static byte[] sign(RSAPrivateKey key, String algorithm, InputStream in)
            throws InvalidKeyException, NoSuchAlgorithmException, IOException, SignatureException {
        Signature signature = Signature.getInstance(algorithm);
        signature.initSign(key);
        byte[] buffer = new byte[4096];
        int len = 0;
        while ((len = in.read(buffer)) != -1) {
            signature.update(buffer, 0, len);
        }
        return signature.sign();
    }

    /**
     * 公钥验签
     * 
     * @param key       公钥
     * @param algorithm 算法
     * @param in        输入数据
     * @param sign      签名
     * @return 签名是否符合
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws SignatureException
     * @throws IOException
     */
    public static boolean validate(RSAPublicKey key, String algorithm, InputStream in, byte[] sign)
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, IOException {
        Signature signature = Signature.getInstance(algorithm);
        signature.initVerify(key);
        byte[] buffer = new byte[4096];
        int len = 0;
        while ((len = in.read(buffer)) != -1) {
            signature.update(buffer, 0, len);
        }
        return signature.verify(sign);
    }

    public PrivateKey loadPrivateKey(String filePath) throws Exception {
        try {
            String keyContent = new String(Files.readAllBytes(Paths.get(filePath)), StandardCharsets.UTF_8)
                    .replaceAll("\\n", "").replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", ""); // Ensure PEM format is cleaned
            byte[] decodedKey = Base64.getDecoder().decode(keyContent);
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decodedKey);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePrivate(spec);
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            logger.error("Failed to load private key", e);
            throw new Exception("Failed to load private key", e);
        }
    }

    public byte[] signData(byte[] data, PrivateKey privateKey) throws Exception {
        try {
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);
            signature.update(data);
            return signature.sign();
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            logger.error("Error signing data", e);
            throw new Exception("Error signing data", e);
        }
    }

    public boolean verifySignature(byte[] data, byte[] signature, PublicKey publicKey) throws Exception {
        try {
            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initVerify(publicKey);
            sig.update(data);
            return sig.verify(signature);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            logger.error("Error verifying signature", e);
            throw new Exception("Error verifying signature", e);
        }
    }

    /**
     * 從指定的密鑰庫中取得私鑰。
     *
     * @param file      密鑰庫的文件路徑
     * @param password  密鑰庫的密碼
     * @param storeType 密鑰庫的類型（例如 "JKS"）
     * @param alias     私鑰在密鑰庫中的別名
     * @return 私鑰
     * @throws Exception 如果在取得私鑰過程中發生錯誤
     */
    public PrivateKey getPrivateKey(String file, char[] password, String storeType, String alias)
            throws Exception {
        logger.debug("Attempting to load a private key from file: {}", file);
        KeyStore keyStore = KeyStore.getInstance(storeType);
        keyStore.load(new FileInputStream(file), password);
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, password);
        logger.info("PrivateKey loaded successfully for alias: {}", alias);
        return privateKey;
    }

    /**
     * 從指定的密鑰庫中取得公鑰。
     *
     * @param file      密鑰庫的文件路徑
     * @param password  密鑰庫的密碼
     * @param storeType 密鑰庫的類型（例如 "JKS"）
     * @param alias     公鑰在密鑰庫中的別名
     * @return 公鑰
     * @throws Exception 如果在取得公鑰過程中發生錯誤
     */
    public PublicKey getPublicKey(String file, char[] password, String storeType, String alias)
            throws Exception {
        logger.debug("Attempting to load a public key from file: {}", file);
        KeyStore keyStore = KeyStore.getInstance(storeType);
        keyStore.load(new FileInputStream(file), password);
        Certificate certificate = keyStore.getCertificate(alias);
        PublicKey publicKey = certificate.getPublicKey();
        logger.info("PublicKey loaded successfully for alias: {}", alias);
        return publicKey;
    }

    /**
     * 使用指定的私鑰和演算法對數據進行簽名。
     *
     * @param message          要簽名的數據
     * @param signingAlgorithm 使用的簽名演算法（例如 "SHA256withRSA"）
     * @param signingKey       進行簽名的私鑰
     * @return 數字簽章
     * @throws SecurityException 如果在簽名過程中發生安全錯誤
     */
    public byte[] sign(byte[] message, String signingAlgorithm, PrivateKey signingKey) throws SecurityException {
        logger.debug("Signing data with algorithm: {}", signingAlgorithm);
        try {
            Signature signature = Signature.getInstance(signingAlgorithm);
            signature.initSign(signingKey);
            signature.update(message);
            byte[] signedData = signature.sign();
            logger.info("Data signed successfully");
            return signedData;
        } catch (GeneralSecurityException exp) {
            logger.error("Error during signature generation", exp);
            throw new SecurityException("Error during signature generation", exp);
        }
    }

    /**
     * 驗證數位簽名的真確性。
     *
     * @param messageBytes     要驗證的消息數據
     * @param signingAlgorithm 使用的簽名演算法（例如 "SHA256withRSA"）
     * @param publicKey        用於驗證簽名的公鑰
     * @param signedData       消息的數位簽名
     * @return 驗證結果為真 (true) 表示簽名有效，否則為假 (false)
     * @throws SecurityException 如果在驗證過程中發生安全錯誤
     */
    public boolean verify(byte[] messageBytes, String signingAlgorithm, PublicKey publicKey, byte[] signedData) {
        logger.debug("Verifying signature with algorithm: {}", signingAlgorithm);
        try {
            Signature signature = Signature.getInstance(signingAlgorithm);
            signature.initVerify(publicKey);
            signature.update(messageBytes);
            boolean isVerified = signature.verify(signedData);
            logger.info("Verification result: {}", isVerified);
            return isVerified;
        } catch (GeneralSecurityException exp) {
            logger.error("Error during verifying", exp);
            throw new SecurityException("Error during verifying", exp);
        }
    }

    /**
     * 使用消息摘要和加密演算法對數據進行簽名。
     *
     * @param messageBytes     原始消息數據
     * @param hashingAlgorithm 使用的哈希演算法（例如 "SHA-256"）
     * @param privateKey       簽名用的私鑰
     * @return 加密後的哈希值（數位簽名）
     * @throws SecurityException 如果在簽名過程中發生安全錯誤
     */
    public byte[] signWithMessageDigestAndCipher(byte[] messageBytes, String hashingAlgorithm,
            PrivateKey privateKey) {
        logger.debug("Signing message with MessageDigest and Cipher using hashing algorithm: {}", hashingAlgorithm);
        try {
            MessageDigest md = MessageDigest.getInstance(hashingAlgorithm);
            byte[] messageHash = md.digest(messageBytes);
            DigestAlgorithmIdentifierFinder hashAlgorithmFinder = new DefaultDigestAlgorithmIdentifierFinder();
            AlgorithmIdentifier hashingAlgorithmIdentifier = hashAlgorithmFinder.find(hashingAlgorithm);
            DigestInfo digestInfo = new DigestInfo(hashingAlgorithmIdentifier, messageHash);
            byte[] hashToEncrypt = digestInfo.getEncoded();

            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, privateKey);
            byte[] encryptedHash = cipher.doFinal(hashToEncrypt);
            logger.info("Message signed with digest and cipher successfully");
            return encryptedHash;
        } catch (GeneralSecurityException | IOException exp) {
            logger.error("Error during signature generation with MessageDigest and Cipher", exp);
            throw new SecurityException("Error during signature generation", exp);
        }
    }

    /**
     * 使用消息摘要和加密演算法驗證數位簽名的真確性。
     *
     * @param messageBytes         原始消息數據
     * @param hashingAlgorithm     使用的哈希演算法（例如 "SHA-256"）
     * @param publicKey            驗證簽名用的公鑰
     * @param encryptedMessageHash 被加密的消息哈希（數位簽名）
     * @return 驗證結果為真 (true) 表示簽名有效，否則為假 (false)
     * @throws SecurityException 如果在驗證過程中發生安全錯誤
     */
    public boolean verifyWithMessageDigestAndCipher(byte[] messageBytes, String hashingAlgorithm,
            PublicKey publicKey, byte[] encryptedMessageHash) {
        logger.debug("Verifying message with MessageDigest and Cipher using hashing algorithm: {}", hashingAlgorithm);
        try {
            MessageDigest md = MessageDigest.getInstance(hashingAlgorithm);
            byte[] newMessageHash = md.digest(messageBytes);
            DigestAlgorithmIdentifierFinder hashAlgorithmFinder = new DefaultDigestAlgorithmIdentifierFinder();
            AlgorithmIdentifier hashingAlgorithmIdentifier = hashAlgorithmFinder.find(hashingAlgorithm);
            DigestInfo digestInfo = new DigestInfo(hashingAlgorithmIdentifier, newMessageHash);
            byte[] hashToEncrypt = digestInfo.getEncoded();

            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, publicKey);
            byte[] decryptedMessageHash = cipher.doFinal(encryptedMessageHash);
            boolean isCorrect = Arrays.equals(decryptedMessageHash, hashToEncrypt);
            logger.info("Verification with digest and cipher result: {}", isCorrect);
            return isCorrect;
        } catch (GeneralSecurityException | IOException exp) {
            logger.error("Error during verifying with MessageDigest and Cipher", exp);
            throw new SecurityException("Error during verifying", exp);
        }
    }

    public byte[] signDataFromFile(Path filePath, PrivateKey privateKey) throws Exception {
        byte[] data = Files.readAllBytes(filePath);
        Signature signature = Signature.getInstance("SHA256WithRSA");
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }

    public boolean verifySignatureFromFile(Path filePath, byte[] signature, PublicKey publicKey) throws Exception {
        byte[] data = Files.readAllBytes(filePath);
        Signature sig = Signature.getInstance("SHA256WithRSA");
        sig.initVerify(publicKey);
        sig.update(data);
        return sig.verify(signature);
    }
}