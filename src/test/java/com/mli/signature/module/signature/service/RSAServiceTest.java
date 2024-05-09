package com.mli.signature.module.signature.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.FileInputStream;
import java.util.Base64;
import java.util.List;

import org.apache.poi.ss.usermodel.Cell;
import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.ss.usermodel.Sheet;
import org.apache.poi.ss.usermodel.Workbook;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.util.ResourceUtils;

import com.mli.signature.module.signature.dao.RSADAO;
import com.mli.signature.module.signature.domain.Key;
import com.mli.signature.module.signature.domain.RSAEntity;

@SpringBootTest
class RSAServiceTest {
    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    @Autowired
    private RSAService rsaService;
    @Autowired
    private RSADAO rsaDAO;

    @Test
    void testCreateKeyPairSignAndVerifyExcelData() throws Exception {
        String username = "testUser";
        String fileName = "TestFile8.xlsx";

        // 读取Excel文件
        File file = ResourceUtils.getFile("input/excel.xlsx");
        FileInputStream fis = new FileInputStream(file);
        Workbook workbook = new XSSFWorkbook(fis);
        Sheet sheet = workbook.getSheetAt(0);
        Row row = sheet.getRow(0);
        Cell cell = row.getCell(0);
        String originalData = cell.getStringCellValue();
        fis.close();
        workbook.close();

        // 将原始数据转换为Base64格式
        String base64Data = Base64.getEncoder().encodeToString(originalData.getBytes());

        // 生成鑰匙對
        Key key = rsaService.createKeyPair();
        assertNotNull(key, "Key pair generation failed");

        // 使用生成的私鑰進行簽名
        String signature = rsaService.signData(base64Data, key.getPrivateKey());
        assertNotNull(signature, "Failed to generate signature");

        // 创建签名记录实体并保存到数据库
        RSAEntity rsaEntity = new RSAEntity();
        rsaEntity.setUsername(username);
        rsaEntity.setName(fileName);
        rsaEntity.setPub(key.getPublicKey());
        rsaEntity.setSignature(signature);
        rsaEntity.setData(base64Data);
        rsaService.insertSignatureRecord(rsaEntity);

        try {
            rsaService.insertSignatureRecord(rsaEntity);
        } catch (RuntimeException ex) {
            System.out.println(ex.getMessage());
        }

        RSAEntity retrievedEntity = rsaService.findSignatureByUsernameAndFileName(username, fileName);
        assertNotNull(retrievedEntity, "Retrieved entity is null");

        logger.info("Original vs Retrieved");
        logger.info("Public Key: {} vs {}", key.getPublicKey(), retrievedEntity.getPub());
        logger.info("Signature: {} vs {}", signature, retrievedEntity.getSignature());
        logger.info("Base64Data: {} vs {}", base64Data, retrievedEntity.getData());

        boolean isSignatureVerified = rsaService.verifySignature(retrievedEntity.getData(),
                retrievedEntity.getPub(), retrievedEntity.getSignature());
        assertTrue(isSignatureVerified, "Signature verification failed using database data");

        assertEquals(true, isSignatureVerified, "All processes should complete successfully using database data");
    }

    @Test
    void testDAONull() {
        String username = "testUser";
        String fileName = "TestFile6.xlsx";
        RSAEntity entity = rsaDAO.findByUsernameAndFileName(username, fileName);
        logger.debug("Retrieved entity: {}", entity);
    }

    @Test
    void testDAOSelectAllNull() {
        String username = "testUser";
        List<RSAEntity> entity = rsaDAO.findByUsername(username);
        logger.debug("Retrieved entity: {}", entity);
    }

}
