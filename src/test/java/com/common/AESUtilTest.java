package com.common;

import com.common.exception.AesCryptoException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

class AESUtilTest {

    private AESUtil aesUtil;

    // 256bit (32 bytes) Base64 인코딩된 키
    private final String base64Key = "uW6+dG5qFev1G0xLhvx0a+GqC8R4AAfI0mX+mHAlKXU=";

    @BeforeEach
    void setUp() {
        aesUtil = new AESUtil();

        // base64Key 필드 수동 주입
        ReflectionTestUtils.setField(aesUtil, "base64Key", base64Key);

        // keySpec도 함께 초기화
        var keySpec = ReflectionTestUtils.invokeMethod(aesUtil, "getKeySpecFromBase64", base64Key);
        ReflectionTestUtils.setField(aesUtil, "keySpec", keySpec);
    }

    @Test
    void testEncryptDecryptSuccess() {
        String plainText = "Hello, World!";
        String encrypted = aesUtil.encrypt(plainText);
        String decrypted = aesUtil.decrypt(encrypted);

        assertNotNull(encrypted);
        assertEquals(plainText, decrypted);
    }

    @Test
    void testDecryptWithTamperedData() {
        String encrypted = aesUtil.encrypt("some data");

        // 일부러 데이터 훼손 (Base64 문자열을 자름)
        String tampered = encrypted.substring(0, encrypted.length() - 4);

        AesCryptoException ex = assertThrows(AesCryptoException.class, () -> {
            aesUtil.decrypt(tampered);
        });
        assertTrue(ex.getMessage().contains("복호화 중 오류 발생"));
    }

    @Test
    void testInvalidKeyLength() {
        AESUtil broken = new AESUtil();
        String badKey = Base64.getEncoder().encodeToString(new byte[10]); // 10바이트짜리 잘못된 키

        ReflectionTestUtils.setField(broken, "base64Key", badKey);

        AesCryptoException ex = assertThrows(AesCryptoException.class, () -> {
            ReflectionTestUtils.invokeMethod(broken, "getKeySpecFromBase64", badKey);
        });
        assertTrue(ex.getMessage().contains("256비트"));
    }

    @Test
    void testInvalidBase64Key() {
        AESUtil broken = new AESUtil();
        String notBase64 = "thisIsNotBase64==";

        ReflectionTestUtils.setField(broken, "base64Key", notBase64);

        AesCryptoException ex = assertThrows(AesCryptoException.class, () -> {
            ReflectionTestUtils.invokeMethod(broken, "getKeySpecFromBase64", notBase64);
        });
        assertTrue(ex.getMessage().contains("Base64"));
    }
}
