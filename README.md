# Excel Digital Signature Application

## Overview

This application provides a way to digitally sign Excel files using Java. It uses Apache POI to handle Excel files and Bouncy Castle for implementing digital signatures. The application is capable of reading an Excel file, signing its content, and then writing the signed content back into a new Excel file.

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

    - swagger:
      http://localhost:8080/swagger-ui/index.html#/

    - 將二進制 key 內容轉換成人類可讀形式：

      `openssl rsa -in privateKey.txt -text`

      `openssl rsa -pubin -in publicKey.txt -text -noout`

2.  數位簽章工具類
    使用前述提供的 DigitalSignatureUtils 類，該類已經包含了基本的數位簽章和驗證功能。

3.  Excel 文件處理服務
    創建一個服務來處理 Excel 文件的讀取、簽名和寫入。

4.  控制器
    創建一個 Spring Boot 控制器來處理 HTTP 請求，實現 Excel 文件的上傳和下載。
