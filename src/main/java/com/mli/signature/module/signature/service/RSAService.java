package com.mli.signature.module.signature.service;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.mli.signature.module.signature.dao.RSADAO;
import com.mli.signature.module.signature.domain.Key;
import com.mli.signature.module.signature.domain.RSAEntity;
import com.mli.signature.module.signature.utility.RSAUtil;

@Service
public class RSAService {
	private final Logger logger = LoggerFactory.getLogger(this.getClass());

	@Autowired
	private RSADAO rsaDAO;
	@Autowired
	private RSAUtil rsaUtil;

	// 生成鑰匙對
	public Key createKeyPair() {
		if (rsaUtil == null) {
			logger.error("RSAUtil not properly injected");
			return null;
		}
		Key key = new Key();
		rsaUtil.createRSAKey(key);
		return key;
	}

	// 使用私鑰進行數字簽名
	public String signData(String body, String privateKey) {
		if (privateKey == null || privateKey.trim().isEmpty()) {
			logger.error("Private key is not provided or is invalid");
			return null;
		}
		return rsaUtil.sign(body, privateKey);
	}

	// 使用公鑰驗證簽名
	public boolean verifySignature(String body, String publicKey, String signature) {
		if (publicKey == null || publicKey.trim().isEmpty() || signature == null || signature.trim().isEmpty()) {
			logger.error("Public key or signature is not provided or is invalid");
			return false;
		}
		boolean verifyFlag = rsaUtil.verify(body, publicKey, signature);
		if (verifyFlag) {
			logger.info("驗證成功");
		} else {
			logger.info("驗證失敗");
		}
		return verifyFlag;
	}

	/**
	 * 插入新的签名记录到数据库。
	 * 
	 * @param record 要插入的签名记录对象。
	 */
	@Transactional
	public void insertSignatureRecord(RSAEntity record) {
		try {
			rsaDAO.insertRSA(record);
		} catch (DuplicateKeyException e) {
			logger.error("Insertion failed: file name already used.");
			throw new RuntimeException("File name '" + record.getName() + "' has already been used.", e);
		}

	}

	/**
	 * 根据用户名查询签名记录列表。
	 * 
	 * @param username 用户名
	 * @return 返回匹配的签名记录列表。
	 */
	@Transactional(readOnly = true)
	public List<RSAEntity> findSignaturesByUsername(String username) {
		return rsaDAO.findByUsername(username);
	}

	/**
	 * 根据用户名和文件名查询具体的签名记录。
	 * 
	 * @param username 用户名
	 * @param 文件名
	 * @return 返回具体的签名记录，如果没有找到返回null。
	 */
	@Transactional(readOnly = true)
	public RSAEntity findSignatureByUsernameAndFileName(String username, String name) {
		return rsaDAO.findByUsernameAndFileName(username, name);
	}
}
