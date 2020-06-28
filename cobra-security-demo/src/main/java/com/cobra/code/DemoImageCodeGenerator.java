package com.cobra.code;

import com.cobra.validate.code.ValidateCodeGenerator;
import com.cobra.validate.code.image.ImageValidateCode;
import org.springframework.web.context.request.ServletWebRequest;

//@Component("imageValidateCodeGenerator")
public class DemoImageCodeGenerator implements ValidateCodeGenerator {
    @Override
    public ImageValidateCode generate(ServletWebRequest request) {
        System.out.println("更高级的图形验证码生成");
        return null;
    }
}
