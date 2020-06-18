package com.cobra.properties;

public class ValidateCodeProperties {

    private ImageValidateCodeProperties image = new ImageValidateCodeProperties();

    private SmsValidateCodeProperties sms = new SmsValidateCodeProperties();

    public ImageValidateCodeProperties getImage() {
        return image;
    }

    public void setImage(ImageValidateCodeProperties image) {
        this.image = image;
    }

    public SmsValidateCodeProperties getSms() {
        return sms;
    }

    public void setSms(SmsValidateCodeProperties sms) {
        this.sms = sms;
    }
}
