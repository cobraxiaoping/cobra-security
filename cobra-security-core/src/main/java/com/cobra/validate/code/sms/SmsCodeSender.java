package com.cobra.validate.code.sms;

/**
 * 短信验证码发送接口
 */
public interface SmsCodeSender {

    void send(String mobile, String code);
}
