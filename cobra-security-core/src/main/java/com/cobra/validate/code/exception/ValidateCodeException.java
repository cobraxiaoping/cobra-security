package com.cobra.validate.code.exception;

import org.springframework.security.core.AuthenticationException;
//AuthenticationException异常是SpringSecurity框架认证异常的基础我们基于基类申明验证码验证异常类
public class ValidateCodeException extends AuthenticationException {
    public ValidateCodeException(String msg, Throwable t) {
        super(msg, t);
    }

    public ValidateCodeException(String msg) {
        super(msg);
    }
}
