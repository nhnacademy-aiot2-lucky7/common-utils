package com.common;

import com.common.exception.AesCryptoException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

class AESUtilTest {

    private static final String RAW_KEY = "12345678901234567890123456789012"; // 32 bytes
    private static final String BASE64_KEY = Base64.getEncoder().encodeToString(RAW_KEY.getBytes());

    @BeforeEach
    void resetKey() {
        System.setProperty("AES_SECRET_KEY", BASE64_KEY);
    }

    @Test
    void testEncryptAndDecrypt() {
        AESUtil aesUtil = new AESUtil();
        String originalText = "Hello, World!";

        String encrypted = aesUtil.encrypt(originalText);
        assertNotNull(encrypted);
        assertNotEquals(originalText, encrypted);

        String decrypted = aesUtil.decrypt(encrypted);
        assertEquals(originalText, decrypted);
    }

    @Test
    void testInvalidKeyLength() {
        String shortKey = Base64.getEncoder().encodeToString("short_key".getBytes());
        System.setProperty("AES_SECRET_KEY", shortKey);

        AesCryptoException exception = assertThrows(
                AesCryptoException.class,
                AESUtil::new
        );

        assertTrue(exception.getMessage().contains("256비트"));
    }

    @Test
    void testInvalidBase64Key() {
        System.setProperty("AES_SECRET_KEY", "not_base64!!!");

        AesCryptoException exception = assertThrows(
                AesCryptoException.class,
                AESUtil::new
        );

        assertTrue(exception.getMessage().contains("Base64"));
    }

    @Test
    void testMissingEnvKey() {
        System.clearProperty("AES_SECRET_KEY");

        AesCryptoException exception = assertThrows(
                AesCryptoException.class,
                AESUtil::new
        );

        assertTrue(exception.getMessage().contains("환경 변수"));
    }
}

