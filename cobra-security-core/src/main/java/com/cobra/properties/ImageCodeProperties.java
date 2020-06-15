package com.cobra.properties;

public class ImageCodeProperties {

    //图形验证码的默认长度
    private int width=67;
    //图形验证码的默认高度
    private int height=23;
    //图形验证码字符串的长度
    private int length=4;
    //图形验证码的失效时间秒
    private int expireIn=60;
    //需要图片验证码的接口
    private String url;

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

    public int getLength() {
        return length;
    }

    public void setLength(int length) {
        this.length = length;
    }

    public int getExpireIn() {
        return expireIn;
    }

    public void setExpireIn(int expireIn) {
        this.expireIn = expireIn;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }
}
