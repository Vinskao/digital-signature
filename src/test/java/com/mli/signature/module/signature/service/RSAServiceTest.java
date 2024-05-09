package com.mli.signature.module.signature.service;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class RSAServiceTest {

    @Autowired
    private RSAService rsaService;

    @Test
    void testVerifyBody() {
        rsaService.verifyBody();

    }

}
