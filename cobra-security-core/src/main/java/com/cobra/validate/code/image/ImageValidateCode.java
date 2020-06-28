package com.cobra.validate.code.image;

import com.cobra.validate.code.ValidateCode;

import java.awt.image.BufferedImage;

public class ImageValidateCode extends ValidateCode {
    //返回给前台展示的验证码图片
    private BufferedImage image;

    public ImageValidateCode(BufferedImage image) {
        this.image = image;
    }

    public ImageValidateCode(String code, int expireTime, BufferedImage image) {
        super(code, expireTime);
        this.image = image;
    }

    public BufferedImage getImage() {
        return image;
    }

    public void setImage(BufferedImage image) {
        this.image = image;
    }


}
