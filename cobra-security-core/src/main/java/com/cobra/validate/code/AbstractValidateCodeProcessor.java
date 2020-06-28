package com.cobra.validate.code;

import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.social.connect.web.HttpSessionSessionStrategy;
import org.springframework.social.connect.web.SessionStrategy;
import org.springframework.web.bind.ServletRequestBindingException;
import org.springframework.web.context.request.ServletWebRequest;

import java.io.IOException;
import java.util.Map;

public abstract class AbstractValidateCodeProcessor<C extends ValidateCode> implements ValidateCodeProcessor {

    /**
     * 操作session的工具类
     */
    private SessionStrategy sessionStrategy = new HttpSessionSessionStrategy();

    /**
     * 收集系统中所有的ValidateCodeGenerator接口的实现类
     */
    @Autowired
    private Map<String, ValidateCodeGenerator> validateCodeGenerators;

    @Override
    public void create(ServletWebRequest request) throws Exception {
        //生成验证码
        C validateCode = generate(request);
        //保存验证码
        save(request, validateCode);
        //发送验证码
        send(request, validateCode);
    }

    public C generate(ServletWebRequest request) {
        String type = getProcessorType(request);
        ValidateCodeGenerator validateCodeGenerator = validateCodeGenerators.get(type + "ValidateCodeGenerator");
        return (C) validateCodeGenerator.generate(request);
    }

    /**
     * 根据请求url 判断是生产图片验证码 还是短信验证码
     * 例如：/code/sms 则获取短信验证码生成器
     * /code/image 则获取图片验证码生成器
     */
    private String getProcessorType(ServletWebRequest request) {
        return StringUtils.substringAfter(request.getRequest().getRequestURI(), "/code/");
    }

    ;

    private void save(ServletWebRequest request, C validateCode) {
        sessionStrategy.setAttribute(request, SESSION_KEY_PREFIX + getProcessorType(request).toUpperCase(), validateCode);
    }

    /**
     * 发送校验码，由子类实现
     **/
    protected abstract void send(ServletWebRequest request, C validateCode) throws IOException, ServletRequestBindingException;
}
