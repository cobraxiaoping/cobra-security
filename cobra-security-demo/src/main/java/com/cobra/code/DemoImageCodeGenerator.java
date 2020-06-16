package com.cobra.code;

import com.cobra.validate.code.ImageCode;
import com.cobra.validate.code.ValidateCodeGenerator;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.ServletWebRequest;

//@Component("imageValidateCodeGenerator")
public class DemoImageCodeGenerator implements ValidateCodeGenerator {
    @Override
    public ImageCode createImageCode(ServletWebRequest request) {
        System.out.println("更高级的图形验证码生成");
        return null;
    }
}
