package com.mli.signature.module.signature.service;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;

import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.test.context.SpringBootTest;
@SpringBootTest
class KeyPairServiceTest {
	private final Logger logger = LoggerFactory.getLogger(this.getClass());

	@Test
	void testGenerateKeyPair() {
		KeyPairService keyPairService = new KeyPairService();
		try {
			KeyPair keyPair = keyPairService.generateKeyPair();
			assertNotNull(keyPair);
			logger.info("Generated key pair: {}", keyPair);

		} catch (Exception e) {
			fail("Exception should not be thrown");
		}
	}

	@Test
	void testSaveKeys() {
		KeyPairService keyPairService = new KeyPairService();
		try {
			KeyPair keyPair = keyPairService.generateKeyPair();
			Path privateKeyPath = Paths.get("privateKey.txt");
			Path publicKeyPath = Paths.get("publicKey.txt");
			keyPairService.saveKeys(keyPair, privateKeyPath, publicKeyPath);

			assertTrue(Files.exists(privateKeyPath));
			assertTrue(Files.exists(publicKeyPath));
			logger.info("Private key saved to: {}", privateKeyPath);
			logger.info("Public key saved to: {}", publicKeyPath);
		} catch (Exception e) {
			fail("Exception should not be thrown");
		}
	}

}
