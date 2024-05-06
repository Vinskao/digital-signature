package com.mli.signature.module.signature.service;

import org.apache.poi.ss.usermodel.*;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.mli.signature.module.signature.utility.DigitalSignatureUtils;

import io.swagger.v3.oas.annotations.Operation;

import java.io.*;
import java.security.PrivateKey;

/**
 * 服務層，提供處理Excel文件的功能，包括讀取、簽名和保存。
 * 
 * @author D3031104
 * @version 1.0
 */
@Service
public class ExcelService {
    @Autowired
    private DigitalSignatureUtils signatureUtils;
    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    /**
     * 讀取Excel文件成為Workbook。
     * 
     * @param filePath Excel文件的路徑
     * @return 讀取到的Workbook
     * @throws IOException 如果文件讀取失敗
     */
    public Workbook readExcel(String filePath) throws IOException {
        logger.info("Attempting to read an Excel file from: {}", filePath);
        FileInputStream fileInputStream = new FileInputStream(filePath);
        Workbook workbook = new XSSFWorkbook(fileInputStream);
        logger.debug("Excel file read successfully from: {}", filePath);
        return workbook;
    }

    /**
     * 將Workbook寫入到文件。
     * 
     * @param workbook 要寫入的Workbook
     * @param filePath 目標文件路徑
     * @throws IOException 如果寫入文件失敗
     */
    public void writeExcel(Workbook workbook, String filePath) throws IOException {
        logger.info("Writing Excel file to: {}", filePath);
        FileOutputStream outputStream = new FileOutputStream(filePath);
        workbook.write(outputStream);
        workbook.close();
        outputStream.close();
        logger.debug("Excel file written successfully to: {}", filePath);
    }

    /**
     * 簽名並保存Excel文件。
     * 
     * @param inputPath  原始文件路徑
     * @param outputPath 簽名後的文件存儲路徑
     * @param privateKey 用於簽名的私鑰
     * @throws Exception 如果簽名或保存過程出錯
     */
    @Operation(summary = "Signs an Excel file using a private key and saves the signed version to the specified path.")
    public void signAndSaveExcel(String inputPath, String outputPath, PrivateKey privateKey) throws Exception {
        logger.info("Signing and saving Excel file. Input: {}, Output: {}", inputPath, outputPath);
        Workbook workbook = readExcel(inputPath);
        Sheet sheet = workbook.getSheetAt(0);
        Cell signatureCell = sheet.createRow(sheet.getLastRowNum() + 1).createCell(0);
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        workbook.write(bos);
        byte[] bytes = bos.toByteArray();
        byte[] signature = signatureUtils.sign(bytes, "SHA256withRSA", privateKey);
        signatureCell.setCellValue(new String(signature)); // 存儲簽章
        logger.debug("Signature added to Excel file, now saving...");
        writeExcel(workbook, outputPath);
        logger.info("Excel file signed and saved successfully to: {}", outputPath);
    }
}
