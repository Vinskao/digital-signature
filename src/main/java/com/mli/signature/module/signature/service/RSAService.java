package com.mli.signature.module.signature.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.mli.signature.module.signature.domain.Entity;
import com.mli.signature.module.signature.utility.RSAUtil;

@Service
public class RSAService {
	private final Logger logger = LoggerFactory.getLogger(this.getClass());

	@Autowired
	private RSAUtil rsaUtil;

	public void verifyBody() {
		if (rsaUtil == null) {
			logger.error("RSAUtil not properly injected");
			return;
		}
		Entity entity = new Entity();
		// 使用RSA算法生成 公钥与私钥, 生成的公私钥 是一一对应的。
		rsaUtil.createRSAKey(entity);
		String body = "123456";
		// 将入参数据以及私钥进行数字加签
		String sign = rsaUtil.sign(body, entity.getPrivateKey());
		// 根据入参数据以及公钥进行验证签名，若入参数据body被修改或者秘钥不正确都会导致验签失败；例如加签使用body，验签使用body2则导致验签失败
		boolean verifyFlag = rsaUtil.verify(body, entity.getPublicKey(), sign);
		if (verifyFlag) {
			logger.info("验签成功");
		} else {
			logger.info("验签失败");
		}
	}
}
