package com.cobra.properties;

public class ImageValidateCodeProperties extends SmsValidateCodeProperties {

    //图形验证码的默认长度
    private int width = 67;
    //图形验证码的默认高度
    private int height = 23;

    public ImageValidateCodeProperties() {
        //覆盖掉父类短信验证码的长度，设置图片验证码的长度为4
        setLength(4);
    }

    public int getWidth() {
        return width;
    }

    public void setWidth(int width) {
        this.width = width;
    }

    public int getHeight() {
        return height;
    }

    public void setHeight(int height) {
        this.height = height;
    }


}
