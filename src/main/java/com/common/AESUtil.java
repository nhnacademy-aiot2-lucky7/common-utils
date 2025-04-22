package com.common;

import com.common.exception.AesCryptoException;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Objects;

/**
 * AES 암호화 및 복호화 유틸리티 클래스.
 * <p>
 * 이 클래스는 AES/GCM/NoPadding 알고리즘을 사용하여 암호화 및 복호화를 수행합니다.
 * 암호화된 결과물은 Base64로 인코딩하여 반환하며, 복호화 시 Base64로 인코딩된 값을 입력으로 받습니다.
 * </p>
 */
public class AESUtil {
    private static final String ALGORITHM = "AES/GCM/NoPadding"; // 사용할 알고리즘
    private static final int IV_SIZE = 12; // IV 크기 (96비트)
    private static final int TAG_BIT_LENGTH = 128; // GCM 태그 비트 길이

    private SecretKeySpec keySpec; // AES 비밀 키 (정적 변수로 변경)

    /**
     * AES 비밀 키를 설정합니다.
     * <p>
     * 이 메서드는 Base64로 인코딩된 AES 비밀 키를 받아, 암호화 및 복호화 작업에 사용할 수 있도록 설정합니다.
     * 비밀 키가 null이거나 빈 값일 경우, {@link AesCryptoException} 예외가 발생합니다.
     * </p>
     *
     * @param aesSecretKey AES 비밀 키 (Base64로 인코딩된 값)
     * @throws AesCryptoException 비밀 키가 null 또는 빈 값일 경우 예외가 발생합니다.
     */
    public void setKey(String aesSecretKey) {
        if (aesSecretKey == null || aesSecretKey.trim().isBlank()) {
            throw new IllegalArgumentException("AES 비밀 키가 null이거나 비어있습니다.");
        }

        keySpec = getKeySpecFromBase64(aesSecretKey); // 키를 정적 변수에 설정
    }

    /**
     * 문자열을 AES 암호화 알고리즘을 사용하여 암호화합니다.
     * <p>
     * 암호화된 결과는 IV(Initialization Vector)와 암호문이 결합된 형태로 Base64로 인코딩하여 반환됩니다.
     * </p>
     *
     * @param plainText 암호화할 평문 문자열
     * @return 암호화된 문자열 (Base64로 인코딩된 값)
     * @throws AesCryptoException 암호화 중 오류 발생 시 예외를 던집니다.
     */
    public String encrypt(String plainText) {
        if(Objects.isNull(keySpec)) {
            throw new AesCryptoException("AES 비밀 키가 설정되지 않았습니다.");
        }

        try {
            // IV 생성
            byte[] iv = generateRandomIV();
            // GCM 매개변수 설정
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(TAG_BIT_LENGTH, iv);

            // 암호화 수행
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
            byte[] encrypted = cipher.doFinal(plainText.getBytes());

            // IV와 암호문을 결합
            byte[] encryptedWithIv = new byte[IV_SIZE + encrypted.length];
            System.arraycopy(iv, 0, encryptedWithIv, 0, IV_SIZE);
            System.arraycopy(encrypted, 0, encryptedWithIv, IV_SIZE, encrypted.length);

            // Base64로 인코딩하여 반환
            return Base64.getEncoder().encodeToString(encryptedWithIv);
        } catch (Exception e) {
            throw new AesCryptoException("암호화 중 오류 발생: " + e);
        }
    }

    /**
     * Base64로 인코딩된 암호문을 AES 알고리즘을 사용하여 복호화합니다.
     * <p>
     * 복호화 시, 암호문과 IV가 결합된 Base64 문자열을 입력받고, 해당 값을 복호화하여 평문을 반환합니다.
     * </p>
     *
     * @param encryptedText 암호화된 문자열 (Base64로 인코딩된 값)
     * @return 복호화된 평문 문자열
     * @throws AesCryptoException 복호화 중 오류 발생 시 예외를 던집니다.
     */
    public String decrypt(String encryptedText) {
        if(Objects.isNull(keySpec)) {
            throw new AesCryptoException("AES 비밀 키가 설정되지 않았습니다.");
        }

        try {
            // Base64로 디코딩
            byte[] decoded = Base64.getDecoder().decode(encryptedText);

            // IV와 암호문 분리
            byte[] iv = new byte[IV_SIZE];
            byte[] encrypted = new byte[decoded.length - IV_SIZE];

            System.arraycopy(decoded, 0, iv, 0, IV_SIZE);
            System.arraycopy(decoded, IV_SIZE, encrypted, 0, encrypted.length);

            // GCM 매개변수 설정
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(TAG_BIT_LENGTH, iv);

            // 복호화 수행
            cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);
            byte[] decrypted = cipher.doFinal(encrypted);

            // 복호화된 데이터를 문자열로 반환
            return new String(decrypted);
        } catch (Exception e) {
            throw new AesCryptoException("복호화 중 오류 발생: " + e);
        }
    }

    /**
     * Base64로 인코딩된 AES 키를 SecretKeySpec 객체로 변환합니다.
     * <p>
     * 이 메서드는 Base64로 인코딩된 AES 키를 디코딩하여, `SecretKeySpec` 객체로 변환합니다.
     * 키 길이가 256비트(32바이트)가 아니면 {@link AesCryptoException} 예외가 발생합니다.
     * </p>
     *
     * @param base64Key Base64로 인코딩된 AES 키
     * @return SecretKeySpec 객체
     * @throws AesCryptoException 키가 Base64로 인코딩되지 않았거나 길이가 잘못된 경우 예외를 던집니다.
     */
    private SecretKeySpec getKeySpecFromBase64(String base64Key) {
        byte[] decodedKey;
        try {
            decodedKey = Base64.getDecoder().decode(base64Key);
        } catch (IllegalArgumentException e) {
            throw new AesCryptoException("AES 키는 Base64로 인코딩된 문자열이어야 합니다.");
        }

        // 키 길이가 256비트(32바이트)여야 합니다.
        if (decodedKey.length != 32) {
            throw new AesCryptoException("AES 키는 256비트(32바이트)여야 합니다. 현재 길이: " + decodedKey.length);
        }

        return new SecretKeySpec(decodedKey, "AES");
    }

    /**
     * 암호화에 사용될 96비트 길이의 랜덤 IV(Initialization Vector)를 생성합니다.
     * <p>
     * 이 메서드는 AES/GCM 모드에서 사용되는 96비트 길이의 랜덤 IV를 생성합니다.
     * </p>
     *
     * @return 생성된 IV 배열
     */
    private byte[] generateRandomIV() {
        byte[] iv = new byte[IV_SIZE];
        new SecureRandom().nextBytes(iv);
        return iv;
    }
}
