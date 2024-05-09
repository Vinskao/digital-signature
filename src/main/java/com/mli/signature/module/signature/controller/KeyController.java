package com.mli.signature.module.signature.controller;

import java.security.KeyPair;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.mli.signature.module.signature.service.KeyPairService;
import java.nio.file.Path;
import java.nio.file.Paths;
import org.springframework.http.HttpStatus;

@RestController
@RequestMapping("/api/keys")
public class KeyController {

    @Autowired
    private KeyPairService keyPairService;

    @GetMapping("/generate")
    public ResponseEntity<?> generateAndSendKeys() {
        try {
            KeyPair keyPair = keyPairService.generateKeyPair();
            Path privateKeyPath = Paths.get("path/to/privateKey");
            Path publicKeyPath = Paths.get("path/to/publicKey");
            keyPairService.saveKeys(keyPair, privateKeyPath, publicKeyPath);

            // 提供下載鏈接或直接發送密鑰檔案
            return ResponseEntity.ok().body("Keys generated successfully. Paths: " + privateKeyPath + ", " + publicKeyPath);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Failed to generate keys: " + e.getMessage());
        }
    }
}