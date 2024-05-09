package com.mli.signature.module.signature.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import org.apache.poi.ss.usermodel.Cell;
import org.apache.poi.ss.usermodel.Sheet;
import org.apache.poi.ss.usermodel.Workbook;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import com.mli.signature.module.signature.utility.DigitalSignatureUtils;

@SpringBootTest
class ExcelServiceTest {
	private final Logger logger = LoggerFactory.getLogger(this.getClass());
	@Autowired
	private DigitalSignatureUtils signatureUtils;
	@Autowired
	private ExcelService excelService;

	@Test
	void testSignAndVerifyFromFile() throws Exception {
		// Path to the text file
		Path path = Paths.get("input/hello.txt");

		// Generate RSA key pair
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(2048);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		PublicKey publicKey = keyPair.getPublic();
		PrivateKey privateKey = keyPair.getPrivate();

		// Sign the data from file
		byte[] signature = signatureUtils.signDataFromFile(path, privateKey);
		String encodedSignature = Base64.getEncoder().encodeToString(signature);
		logger.info("Generated Digital Signature: {}", encodedSignature);

		// Verify the signature
		boolean isValid = signatureUtils.verifySignatureFromFile(path, signature, publicKey);
		logger.info("Signature verification result: {}", isValid);

		// Assert the signature is valid
		assertTrue(isValid, "The digital signature should be valid.");
	}

	@Test
	void testSignAndVerifyData() throws Exception {
		// Generate RSA key pair
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(2048);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
		RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

		// Data to sign
		byte[] data = "Hello, this is a test.".getBytes();

		// Sign the data
		byte[] signature = DigitalSignatureUtils.sign(privateKey, "SHA256WithRSA", new ByteArrayInputStream(data));
		String encodedSignature = Base64.getEncoder().encodeToString(signature);
		logger.info("Generated Digital Signature: {}", encodedSignature);

		// Verify the signature
		boolean isValid = DigitalSignatureUtils.validate(publicKey, "SHA256WithRSA", new ByteArrayInputStream(data),
				signature);
		logger.info("Signature verification result: {}", isValid);

		// Assert the signature is valid
		assertTrue(isValid, "The digital signature should be valid.");
	}

	@Test
	void testReadExcel() throws Exception {
		// Create a simple Excel file as byte array
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		Workbook workbook = new XSSFWorkbook();
		workbook.createSheet().createRow(0).createCell(0).setCellValue("Test");
		workbook.write(bos);
		workbook.close();
		ByteArrayInputStream bis = new ByteArrayInputStream(bos.toByteArray());

		// Test readExcel with ByteArrayInputStream mimicking a file input
		Workbook resultWorkbook = excelService.readExcel(bis);
		assertNotNull(resultWorkbook);

		// Get the cell value and convert it to a string
		String cellValue = resultWorkbook.getSheetAt(0).getRow(0).getCell(0).getStringCellValue();
		logger.info("Cell value: {}", cellValue); // Print the cell value

		// Assert the cell value
		assertEquals("Test", cellValue);
		logger.info("ReadExcel test completed successfully.");
	}

	@Test
	void testWriteExcel() throws Exception {
		String path = "output/test-write.xlsx";
		Workbook workbook = new XSSFWorkbook();
		ByteArrayOutputStream bos = new ByteArrayOutputStream();

		workbook.write(bos);

		excelService.writeExcel(workbook, path);
		// 驗證文件是否寫入
		assertTrue(Files.exists(Paths.get(path)));
		logger.info("WriteExcel test completed successfully.");

		workbook.close();
	}

	@Test
	void testSignAndVerifyExcel() throws Exception {
		String keystorePath = "keystore.jks";
		char[] keystorePassword = "keystorePassword".toCharArray();
		String keystoreType = "JKS"; // or "PKCS12", depending on your keystore type
		String alias = "yourCertAlias";

		PrivateKey privateKey = signatureUtils.loadPrivateKey("privateKey.txt");
		PublicKey publicKey = signatureUtils.getPublicKey(keystorePath, keystorePassword, keystoreType, alias);

		Path inputPath = Paths.get("input/excel.xlsx");
		Path outputPath = Paths.get("output/signed-excel.xlsx");
		assertTrue(Files.exists(inputPath), "Input file does not exist.");

		byte[] data = Files.readAllBytes(inputPath);
		byte[] signature = signatureUtils.signData(data, privateKey);

		// Assuming you have added methods signData and verifySignature accordingly
		try (Workbook workbook = new XSSFWorkbook()) {
			Sheet sheet = workbook.createSheet("Signature");
			Cell signatureCell = sheet.createRow(0).createCell(0);
			signatureCell.setCellValue(Base64.getEncoder().encodeToString(signature));
			ByteArrayOutputStream bos = new ByteArrayOutputStream();
			workbook.write(bos);
			Files.write(outputPath, bos.toByteArray());
		}

		assertTrue(Files.exists(outputPath), "Output file was not created.");
		assertTrue(signatureUtils.verifySignature(data, signature, publicKey), "Failed to verify the signature.");
	}

	@Test
	void testSignAndGenerateFile() throws Exception {
		// Input path to the text file
		Path inputPath = Paths.get("input/hello.txt");
		// Output path for the signed file
		Path outputPath = Paths.get("output/hello_signed.txt");
		// Path to save the public key
		Path publicKeyPath = Paths.get("keys/public_key.pub");

		// Generate RSA key pair
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(2048);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		PrivateKey privateKey = keyPair.getPrivate();
		PublicKey publicKey = keyPair.getPublic();

		// Save the public key to file
		byte[] publicKeyBytes = publicKey.getEncoded();
		Files.write(publicKeyPath, publicKeyBytes);

		// Sign the data from file and write to output file
		byte[] signature = signatureUtils.signDataFromFile(inputPath, privateKey);
		Files.write(outputPath, signature);

		// Log the success message
		logger.info("Digital signature generated and saved to file: {}", outputPath);
	}

	@Test
	void testReadAndVerifyFile() throws Exception {
		// Input path to the signed file
		Path inputPath = Paths.get("output/hello_signed.txt");
		// Public key path
		Path publicKeyPath = Paths.get("keys/public_key.pub");

		// Read the signed data from output file
		byte[] signedData = Files.readAllBytes(inputPath);

		// Get public key
		byte[] publicKeyBytes = Files.readAllBytes(publicKeyPath);
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PublicKey publicKey = keyFactory.generatePublic(keySpec);

		// Verify the signature
		boolean isValid = signatureUtils.verifySignatureFromFile(inputPath, signedData, publicKey);
		logger.info("Signature verification result: {}", isValid);

		// Assert the signature is valid
		assertTrue(isValid, "The digital signature should be valid.");
	}

}