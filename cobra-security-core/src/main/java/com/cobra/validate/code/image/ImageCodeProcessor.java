package com.cobra.validate.code.image;

import com.cobra.validate.code.AbstractValidateCodeProcessor;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.ServletRequestBindingException;
import org.springframework.web.context.request.ServletWebRequest;

import javax.imageio.ImageIO;
import java.io.IOException;

@Component("imageCodeProcessor")
public class ImageCodeProcessor extends AbstractValidateCodeProcessor<ImageValidateCode> {

    /**
     * 发送图形验证码图片，将其写入到响应中
     */
    @Override
    protected void send(ServletWebRequest request, ImageValidateCode validateCode) throws IOException, ServletRequestBindingException {
        ImageIO.write(validateCode.getImage(), "JPEG", request.getResponse().getOutputStream());

    }

}
