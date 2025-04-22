package com.common;

import com.common.exception.AesCryptoException;
import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

class AESUtilTest {

    private static final String RAW_KEY = "12345678901234567890123456789012"; // 32 bytes, AES-256 비밀 키
    private static final String BASE64_KEY = Base64.getEncoder().encodeToString(RAW_KEY.getBytes());

    @Test
    void testEncryptAndDecrypt() {
        // BASE64_KEY를 직접 생성자에 전달하여 AESUtil 객체를 생성합니다.
        AESUtil aesUtil = new AESUtil();
        aesUtil.setKey(BASE64_KEY);
        String originalText = "Hello, World!"; // 테스트할 평문

        // 암호화
        String encrypted = aesUtil.encrypt(originalText);
        assertNotNull(encrypted); // 암호화된 값이 null이 아님을 확인
        assertNotEquals(originalText, encrypted); // 암호화된 값이 평문과 다름을 확인

        // 복호화
        String decrypted = aesUtil.decrypt(encrypted);
        assertEquals(originalText, decrypted); // 복호화된 값이 원본 평문과 같음 확인
    }

    // Base64가 아닌 키 사용 시 예외 발생 확인
    @Test
    void testInvalidKeyLength() {
        String shortKey = Base64.getEncoder().encodeToString("short_key".getBytes()); // 길이가 짧은 키
        // AESUtil 객체를 생성할 때, 잘못된 키를 사용해 테스트
        AesCryptoException exception = assertThrows(
                AesCryptoException.class,
                () -> {
                    AESUtil aesUtil = new AESUtil();
                    aesUtil.setKey(shortKey);
                }
        );

        assertTrue(exception.getMessage().contains("256비트")); // 메시지에 '256비트'가 포함되어 있는지 확인
    }

    // 키 길이 부족 시 예외 발생 확인
    @Test
    void testInvalidBase64Key() {
        String invalidBase64Key = "not_base64!!!"; // 잘못된 Base64 키 설정

        // AESUtil 객체를 생성할 때 예외가 발생하는지 확인
        AesCryptoException exception = assertThrows(
                AesCryptoException.class,
                () -> {
                    AESUtil aesUtil = new AESUtil();
                    aesUtil.setKey(invalidBase64Key);
                }
        );

        assertTrue(exception.getMessage().contains("Base64")); // 메시지에 'Base64'가 포함되어 있는지 확인
    }

    @Test
    void testMissingEnvKey() {
        // AESUtil 객체를 생성할 때 예외가 발생하는지 확인
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> {
                    AESUtil aesUtil = new AESUtil();
                    aesUtil.setKey(null);
                }
        );

        assertTrue(exception.getMessage().contains("AES 비밀 키가 null이거나 비어있습니다.")); // 메시지에 'AES 비밀 키가 설정되지 않았습니다.'가 포함되어 있는지 확인
    }
}
