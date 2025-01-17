# Excel Digital Signature APP

## 概念
給定一個.xlsx文件，對其數位簽章(創建一個單元格放置簽名)後保存為byte，簽章以後的任何形式修改.xlsx，都會使驗章程式發現文件被串改。

## 技術 Overview

該應用程式提供了一種使用 Java 對 Excel 檔案進行數位簽章的方法。它使用 Apache POI 處理 Excel 文件，使用 Bouncy Castle 實現數位簽章。該應用程式能夠讀取 Excel 文件、對其內容進行簽名，然後將簽名的內容寫回新的 Excel 文件中。

1.  環境設置
    首先，確保你的 Spring Boot 應用程序已經添加了以下依賴：

        - Apache POI（處理 Excel 文件）
        - Bouncy Castle（數位簽章）

    在 pom.xml 中添加依賴：

    ```xml
    <dependency>
        <groupId>org.apache.poi</groupId>
        <artifactId>poi-ooxml</artifactId>
        <version>5.0.0</version>
    </dependency>
    <dependency>
        <groupId>org.bouncycastle</groupId>
        <artifactId>bcprov-jdk15on</artifactId>
        <version>1.68</version>
    </dependency>
    ```
swagger: `http://localhost:8080/swagger-ui/index.html#/`

將二進制 key 內容轉換成人類可讀形式：
```bash
openssl rsa -in privateKey.txt -text
openssl rsa -pubin -in publicKey.txt -text -noout
```

2.  數位簽章工具類
    使用前述提供的 DigitalSignatureUtils 類，該類已經包含了基本的數位簽章和驗證功能。

3.  Excel 文件處理服務
    創建一個服務來處理 Excel 文件的讀取、簽名和寫入。

4.  控制器
    創建一個 Spring Boot 控制器來處理 HTTP 請求，實現 Excel 文件的上傳和下載。


## 詳細流程
1. 生成一對private/public keys

2. ExcelController.uploadAndSignExcel
    - 參數:
        - file: 用戶上傳的 Excel 文件，類型是 MultipartFile。
        - privateKey: 用於簽名的私鑰，類型是 PrivateKey。
    - 流程:
        - file.transferTo(tempFile.toFile()): 把上傳的 Excel 文件轉存到臨時文件 tempFile 中。
        - 調用 excelService.signAndSaveExcel 方法對文件進行簽名，並將簽名後的文件保存到指定的路徑。
        - 返回簽名後的文件下載鏈接。
3. ExcelService.signAndSaveExcel
    - 參數:
        - inputPath: 原始 Excel 文件的路徑。
        - outputPath: 簽名後的 Excel 文件保存路徑。
        - privateKey: 用於簽名的私鑰。
    - 流程:
        - 調用 readExcel(inputPath) 方法讀取 Excel 文件。
        - 調用 DigitalSignatureUtils.sign 方法對文件進行簽名，並將簽名結果存儲在 signatureCell 中。
        - 調用 writeExcel(workbook, outputPath) 保存簽名後的 Excel 文件。
4. DigitalSignatureUtils.sign
    - 參數:
        - message: 要簽名的數據（即轉換為字節數組的 Excel 文件內容）。
        - signingAlgorithm: 簽名算法（例如 SHA256withRSA）。
        - signingKey: 用於簽名的私鑰。
    - 流程:
        - Signature.getInstance(signingAlgorithm): 創建簽名算法的實例。
        - signature.initSign(signingKey): 使用私鑰初始化簽名。
        - signature.update(message): 更新簽名數據。
        - signature.sign(): 執行簽名並返回簽名結果。
5. DigitalSignatureUtils.verify
    - 參數:
        - messageBytes: 用於驗證的消息數據。
        - signingAlgorithm: 簽名算法（例如 SHA256withRSA）。
        - publicKey: 用於驗證簽名的公鑰。
        - signedData: 要驗證的數位簽名。
    - 流程:
        - Signature.getInstance(signingAlgorithm): 創建簽名算法的實例。
        - signature.initVerify(publicKey): 使用公鑰初始化驗證。
        - signature.update(messageBytes): 更新驗證數據。
        - signature.verify(signedData): 驗證簽名結果。
