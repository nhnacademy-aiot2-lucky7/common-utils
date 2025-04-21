package com.common.exception;

/**
 * AES 암호화 관련 오류를 처리하는 예외 클래스입니다.
 * <p>
 * 이 예외는 AES 알고리즘을 사용한 암호화 또는 복호화 중 발생하는 오류를 처리하기 위해 사용됩니다.
 * </p>
 */
public class AesCryptoException extends RuntimeException {
    /**
     * 지정된 메시지를 사용하여 {@link AesCryptoException} 예외를 생성합니다.
     *
     * @param message 예외 메시지
     */
    public AesCryptoException(String message) {
        super(message);
    }
}
