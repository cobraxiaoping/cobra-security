package com.cobra.validate.code;

import com.cobra.properties.SecurityProperties;
import com.cobra.validate.code.sms.DefaultSmsCodeSender;
import com.cobra.validate.code.sms.SmsCodeSender;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class ValidateCodeBeanConfig {

    @Autowired
    private SecurityProperties securityProperties;


    /**
     * 注意这里用了一个注解@ConditionalOnMissingBean 在应用启动的时候会先去容器中查找名为imageValidateCodeGenerator的bean如果没有查找到则创建默认的生成逻辑
     */
    @Bean
    @ConditionalOnMissingBean(name = "imageValidateCodeGenerator")
    public ValidateCodeGenerator imageValidateCodeGenerator() {
        DefaultImageValidateCodeGenerator validateCodeGenerator = new DefaultImageValidateCodeGenerator();
        validateCodeGenerator.setSecurityProperties(securityProperties);
        return validateCodeGenerator;
    }

    /**
     * 注意这里用了一个注解@ConditionalOnMissingBean 在应用启动的时候会先去容器中查找SmsCodeSender类的实现的bean如果没有查找到则创建默认的生成逻辑
     */
    @Bean
    @ConditionalOnMissingBean(SmsCodeSender.class)
    public SmsCodeSender smsCodeSender() {
        return new DefaultSmsCodeSender();
    }

    /**
     * 注意这里用了一个注解@ConditionalOnMissingBean 在应用启动的时候会先去容器中查找名为smsValidateCodeGenerator的bean如果没有查找到则创建默认的生成逻辑
     */
    @Bean
    @ConditionalOnMissingBean(name = "smsValidateCodeGenerator")
    public ValidateCodeGenerator smsValidateCodeGenerator() {
        DefaultSmsValidateCodeGenerator validateCodeGenerator = new DefaultSmsValidateCodeGenerator();
        validateCodeGenerator.setSecurityProperties(securityProperties);
        return validateCodeGenerator;
    }

}
