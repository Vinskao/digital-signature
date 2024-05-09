package com.mli.signature.module.signature.utility;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import com.mli.signature.module.signature.domain.Key;

@Component
public class RSAUtil {
    private final Logger logger = LoggerFactory.getLogger(this.getClass());
    private String encryptionAlgorithm = "RSA";
    private String signAlgorithm = "MD5withRSA";

    /**
     * 生成对应的 与我通信的公钥和私钥
     * 
     * @return
     */
    public void createRSAKey(Key entity) {
        try {
            // 创建KeyPairGenerator 指定算法为RSA，用于生成对应的公钥和私钥
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(encryptionAlgorithm);
            // 指定字节长度
            keyPairGenerator.initialize(1024);

            // 秘钥生成器
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            // 公钥
            RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
            // 进行Base64编码存入
            String clientPublicKey = Base64.encodeBase64String(publicKey.getEncoded());
            logger.info("生成的clientPublicKey是: {}", clientPublicKey);
            entity.setPublicKey(clientPublicKey);

            // 私钥
            RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
            // 进行Base64编码存入
            String clientPrivateKey = Base64.encodeBase64String(privateKey.getEncoded());
            logger.info("生成的clientPrivateKey是: {}", clientPrivateKey);
            entity.setPrivateKey(clientPrivateKey);
        } catch (Exception e) {
            logger.error("生成秘钥失败");
            e.printStackTrace();
        }
    }

    /**
     * 利用私钥信息生成数字签名
     * 
     * @param data       入参数据body
     * @param privateKey 私钥
     * @return
     */
    public String sign(String data, String privateKey) {
        try {
            // 入参数据body字节数组
            byte[] dataBytes = data.getBytes();
            // 获取私钥秘钥字节数组
            byte[] keyBytes = Base64.decodeBase64(privateKey);
            // 使用给定的编码密钥创建一个新的PKCS8EncodedKeySpec。
            // PKCS8EncodedKeySpec 是 PKCS#8标准作为密钥规范管理的编码格式
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
            // 实例化KeyFactory,指定为加密算法 为 RSA
            KeyFactory keyFactory = KeyFactory.getInstance(encryptionAlgorithm);
            // 获得PrivateKey对象
            PrivateKey privateKey1 = keyFactory.generatePrivate(keySpec);
            // 用私钥对信息生成数字签名，指定签名算法为 MD5withRSA
            Signature signature = Signature.getInstance(signAlgorithm);
            // 初始化签名
            signature.initSign(privateKey1);
            // 数据body带入
            signature.update(dataBytes);
            // 对签名进行Base64编码
            return Base64.encodeBase64String(signature.sign());
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 利用公钥校验数字签名
     * 
     * @param data      入参数据body
     * @param publicKey 公钥
     * @param sign      签名
     * @return
     */
    public boolean verify(String data, String publicKey, String sign) {
        try {
            // 入参数据body字节数组
            byte[] dataBytes = data.getBytes("UTF-8");
            // 获取公钥秘钥字节数组
            byte[] keyBytes = Base64.decodeBase64(publicKey);
            // 使用给定的编码密钥创建一个新的X509EncodedKeySpec
            // X509EncodedKeySpec是基于X.509证书提前的公钥，一种java秘钥规范
            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(keyBytes);
            // 实例化KeyFactory,指定为加密算法 为 RSA
            KeyFactory keyFactory = KeyFactory.getInstance(encryptionAlgorithm);
            // 获取publicKey对象
            PublicKey publicKey1 = keyFactory.generatePublic(x509EncodedKeySpec);
            // 用私钥对信息生成数字签名，指定签名算法为 MD5withRSA
            Signature signature = Signature.getInstance(signAlgorithm);
            // 带入公钥进行验证
            signature.initVerify(publicKey1);
            // 数据body带入
            signature.update(dataBytes);
            // 验证签名
            return signature.verify(Base64.decodeBase64(sign));
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }
}
