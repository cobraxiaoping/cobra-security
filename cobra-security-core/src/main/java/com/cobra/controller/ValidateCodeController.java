package com.cobra.controller;

import com.cobra.properties.SecurityProperties;
import com.cobra.validate.code.ImageCode;
import com.cobra.validate.code.ValidateCodeGenerator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.social.connect.web.HttpSessionSessionStrategy;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.ServletRequestUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.social.connect.web.SessionStrategy;
import org.springframework.web.context.request.ServletWebRequest;

import javax.imageio.ImageIO;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.IOException;
import java.util.Random;


@RestController
public class ValidateCodeController {

    //Session中用户来存放验证码的KEY
    public static final String SESSION_KEY = "SESSION_KEY_IMAGE_CODE";

    //使用依赖spring-social-web 中提供的Session操作用户来操作Session
    private SessionStrategy sessionStrategy = new HttpSessionSessionStrategy();

    @Autowired
    private ValidateCodeGenerator imageValidateCodeGenerator;

    @GetMapping("/code/image")
    public void createCode(HttpServletRequest request, HttpServletResponse response) throws IOException {

        //第一步创建图片验证码
        ImageCode imageCode = imageValidateCodeGenerator.createImageCode( new ServletWebRequest(request));

        //第二步将验证码放入Session中
        sessionStrategy.setAttribute(new ServletWebRequest(request), SESSION_KEY, imageCode);

        //第三步将图片验证码写入到响应中
        ImageIO.write(imageCode.getImage(), "JPEG", response.getOutputStream());
    }


}
