package com.common;

import com.common.exception.AesCryptoException;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.lang.reflect.Method;

import static org.junit.jupiter.api.Assertions.*;

class AESUtilTest {

    // 정상 암복호화 테스트
    @Test
    void testEncryptAndDecrypt() throws Exception {
        String plainText = "Hello, World!";
        String base64Key = "12345678901234567890123456789012"; // 32바이트를 Base64로 인코딩

        String encodedKey = java.util.Base64.getEncoder().encodeToString(base64Key.getBytes());

        AESUtil aesUtil = new AESUtil();
        injectBase64Key(aesUtil, encodedKey);
        invokeInit(aesUtil);

        String encrypted = aesUtil.encrypt(plainText);
        String decrypted = aesUtil.decrypt(encrypted);

        assertEquals(plainText, decrypted);
    }

    // Base64가 아닌 키 사용 시 예외 발생 확인
    @Test
    void testInvalidBase64Key() throws Exception {
        AESUtil aesUtil = new AESUtil();
        injectBase64Key(aesUtil, "not-base64@@@");

        Exception exception = assertThrows(Exception.class, () -> invokeInit(aesUtil));
        Throwable cause = exception.getCause(); // InvocationTargetException → getCause()
        assertInstanceOf(AesCryptoException.class, cause);
        assertTrue(cause.getMessage().contains("Base64"));
    }

    // 키 길이 부족 시 예외 발생 확인
    @Test
    void testInvalidKeyLength() throws Exception {
        String shortKey = "short-key"; // 길이 부족

        AESUtil aesUtil = new AESUtil();
        String encoded = java.util.Base64.getEncoder().encodeToString(shortKey.getBytes());
        injectBase64Key(aesUtil, encoded);

        Exception exception = assertThrows(Exception.class, () -> invokeInit(aesUtil));
        Throwable cause = exception.getCause();
        assertInstanceOf(AesCryptoException.class, cause);
        assertTrue(cause.getMessage().contains("256비트"));
    }

    // 리플렉션 유틸 메서드
    private void injectBase64Key(AESUtil aesUtil, String keyValue) throws Exception {
        Field field = AESUtil.class.getDeclaredField("base64Key");
        field.setAccessible(true);
        field.set(aesUtil, keyValue);
    }

    private void invokeInit(AESUtil aesUtil) throws Exception {
        Method method = AESUtil.class.getDeclaredMethod("init");
        method.setAccessible(true);
        method.invoke(aesUtil);
    }
}
