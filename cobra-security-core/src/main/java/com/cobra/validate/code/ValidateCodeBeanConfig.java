package com.cobra.validate.code;

import com.cobra.properties.SecurityProperties;
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
     * */
    @Bean
    @ConditionalOnMissingBean(name="imageValidateCodeGenerator")
    public ValidateCodeGenerator imageValidateCodeGenerator(){
        DefaultValidateCodeGenerator validateCodeGenerator = new DefaultValidateCodeGenerator();
        validateCodeGenerator.setSecurityProperties(securityProperties);
        return  validateCodeGenerator;
    }
}
