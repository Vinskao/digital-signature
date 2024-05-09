package com.mli.signature.module.signature.controller;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import com.mli.signature.module.signature.service.ExcelService;

import io.swagger.v3.oas.annotations.Operation;

/**
 * 控制器用於處理有關Excel文件的操作，包括上傳和簽署Excel文件。
 * 
 * @author D3031104
 * @version 1.0
 */
@RestController
@RequestMapping("/api/excel")
public class ExcelController {
    @Autowired
    private ExcelService excelService;
    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    /**
     * 接收一個Excel文件和私鑰，進行數位簽章，並返回簽章後文件的下載連結。
     *
     * @param file       上傳的Excel文件
     * @param privateKey 用於簽名的私鑰
     * @return 簽名後文件的下載URL或錯誤消息
     */
    @Operation(summary = "Provides a signed version of the uploaded Excel file.")
    @PostMapping("/upload")
    public String uploadAndSignExcel(@RequestParam("file") MultipartFile file,
            @RequestParam("privateKey") PrivateKey privateKey) {
        logger.info("Received a request to sign an Excel file.");
        Path tempFile;
        try {
            tempFile = Files.createTempFile("upload-", ".xlsx");
            file.transferTo(tempFile.toFile());
            logger.debug("Temporary file created at {}", tempFile.toAbsolutePath().toString());
        } catch (Exception e) {
            logger.error("Failed to create a temporary file", e);
            return "Error in creating temporary file.";
        }

        try {
            String outputPath = tempFile.toAbsolutePath().toString().replace(".xlsx", "-signed.xlsx");
            logger.debug("Signing the Excel file.");

            // 將文件路徑轉換為 InputStream
            InputStream inputStream = Files.newInputStream(tempFile);

            excelService.signAndSaveExcel(inputStream, outputPath, privateKey);
            logger.info("File signed successfully. Available for download at: {}", outputPath);
            return "File signed successfully. Download at: " + outputPath;
        } catch (Exception e) {
            logger.error("Error processing file", e);
            return "Error processing file.";
        }
    }
}