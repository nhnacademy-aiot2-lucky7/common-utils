package com.common;

import com.common.exception.AesCryptoException;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

@Slf4j
@Component
public class AESUtil {

    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int IV_SIZE = 12;
    private static final int TAG_BIT_LENGTH = 128;

    @Value("${aes.secret.key}")
    private String base64Key;

    private SecretKeySpec keySpec;

    @PostConstruct
    private void init() {
        if (base64Key == null || base64Key.trim().isBlank()) {
            throw new AesCryptoException("AES 대칭키가 설정되지 않았습니다.");
        }
        this.keySpec = getKeySpecFromBase64(base64Key);
    }

    public String encrypt(String plainText) {
        try {
            byte[] iv = generateRandomIV();
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(TAG_BIT_LENGTH, iv);

            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
            byte[] encrypted = cipher.doFinal(plainText.getBytes());

            byte[] encryptedWithIv = new byte[IV_SIZE + encrypted.length];
            System.arraycopy(iv, 0, encryptedWithIv, 0, IV_SIZE);
            System.arraycopy(encrypted, 0, encryptedWithIv, IV_SIZE, encrypted.length);

            return Base64.getEncoder().encodeToString(encryptedWithIv);
        } catch (Exception e) {
            throw new AesCryptoException("암호화 중 오류 발생: " + e.getMessage());
        }
    }

    public String decrypt(String encryptedText) {
        try {
            byte[] decoded = Base64.getDecoder().decode(encryptedText);

            byte[] iv = new byte[IV_SIZE];
            byte[] encrypted = new byte[decoded.length - IV_SIZE];

            System.arraycopy(decoded, 0, iv, 0, IV_SIZE);
            System.arraycopy(decoded, IV_SIZE, encrypted, 0, encrypted.length);

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(TAG_BIT_LENGTH, iv);

            cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);
            byte[] decrypted = cipher.doFinal(encrypted);

            return new String(decrypted);
        } catch (Exception e) {
            throw new AesCryptoException("복호화 중 오류 발생: " + e.getMessage());
        }
    }

    private SecretKeySpec getKeySpecFromBase64(String base64Key) {
        byte[] decodedKey;
        try {
            decodedKey = Base64.getDecoder().decode(base64Key);
        } catch (IllegalArgumentException e) {
            throw new AesCryptoException("AES 키는 Base64로 인코딩된 문자열이어야 합니다.");
        }

        if (decodedKey.length != 32) {
            throw new AesCryptoException("AES 키는 256비트(32바이트)여야 합니다. 현재 길이: " + decodedKey.length);
        }

        return new SecretKeySpec(decodedKey, "AES");
    }

    private byte[] generateRandomIV() {
        byte[] iv = new byte[IV_SIZE];
        new SecureRandom().nextBytes(iv);
        return iv;
    }
}
