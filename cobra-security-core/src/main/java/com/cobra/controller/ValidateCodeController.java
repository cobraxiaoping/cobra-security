package com.cobra.controller;

import com.cobra.validate.code.ValidateCodeProcessor;
import org.apache.commons.lang.RandomStringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.request.ServletWebRequest;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Map;


@RestController
public class ValidateCodeController {

    private Logger log = LoggerFactory.getLogger(ValidateCodeController.class);

    @Autowired
    private Map<String, ValidateCodeProcessor> validateCodeProcessor;
    public static final String SESSION_KEY = "SESSION_KEY_IMAGE_CODE";
    /*
    //Session中用户来存放验证码的KEY


    //使用依赖spring-social-web 中提供的Session操作用户来操作Session
    private SessionStrategy sessionStrategy = new HttpSessionSessionStrategy();

    @Autowired
    private ValidateCodeGenerator imageValidateCodeGenerator;

    @Autowired
    private ValidateCodeGenerator smsValidateCodeGenerator;

    @Autowired
    private SmsCodeSender smsCodeSender;



    @GetMapping("/code/image")
    public void createCode(HttpServletRequest request, HttpServletResponse response) throws IOException {

        //第一步创建图片验证码
        ImageValidateCode imageCode = (ImageValidateCode) imageValidateCodeGenerator.generate(new ServletWebRequest(request));

        //第二步将验证码放入Session中
        sessionStrategy.setAttribute(new ServletWebRequest(request), SESSION_KEY, imageCode);

        //第三步将图片验证码写入到响应中
        ImageIO.write(imageCode.getImage(), "JPEG", response.getOutputStream());
    }



    @GetMapping("/code/sms")
    public void createSmsCode(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletRequestBindingException {

        //第一步创建短信验证码
        ValidateCode validateCode = smsValidateCodeGenerator.generate(new ServletWebRequest(request));

        //第二步将验证码放入Session中
        sessionStrategy.setAttribute(new ServletWebRequest(request), SESSION_KEY, validateCode);

        //第三步通过短信服务商将短信验证码发出
        String mobile = ServletRequestUtils.getRequiredStringParameter(request, "mobile");
        smsCodeSender.send(mobile, validateCode.getCode());

    }
     */

    /**
     * 创建验证码，根据验证码类型不同，调用不同的validateCodeProcessor接口实现类
     */
    @GetMapping("/code/{type}")
    public void createCode(HttpServletRequest request, HttpServletResponse response, @PathVariable String type) throws Exception {
        validateCodeProcessor.get(type + "CodeProcessor").create(new ServletWebRequest(request, response));
    }


    @GetMapping("/code/xiao")
    public String createCode(HttpServletRequest request, HttpServletResponse response) throws Exception {
        return RandomStringUtils.randomAlphanumeric(6);
    }
}
