package com.cobra.properties;

public class SmsValidateCodeProperties {

    //验证码字符串的长度
    private int length = 6;
    //验证码的失效时间秒
    private int expireIn = 60;

    //需要图片验证码的接口
    private String url;

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
