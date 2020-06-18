package com.cobra.controller;

import com.cobra.validate.code.ImageValidateCode;
import com.cobra.validate.code.ValidateCode;
import com.cobra.validate.code.ValidateCodeGenerator;
import com.cobra.validate.code.sms.SmsCodeSender;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.social.connect.web.HttpSessionSessionStrategy;
import org.springframework.social.connect.web.SessionStrategy;
import org.springframework.web.bind.ServletRequestBindingException;
import org.springframework.web.bind.ServletRequestUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.request.ServletWebRequest;

import javax.imageio.ImageIO;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;


@RestController
public class ValidateCodeController {

    private Logger log = LoggerFactory.getLogger(ValidateCodeController.class);

    //Session中用户来存放验证码的KEY
    public static final String SESSION_KEY = "SESSION_KEY_IMAGE_CODE";

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

}
