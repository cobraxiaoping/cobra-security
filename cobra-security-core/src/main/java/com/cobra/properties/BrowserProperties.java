package com.cobra.properties;

public class BrowserProperties {
    //设置默认登录页面，如果配置了com.cobra.security.browser.loginPage 则会覆盖默认登录页面
    private String loginPage="/default-singIn.html";

    public String getLoginPage() {
        return loginPage;
    }

    public void setLoginPage(String loginPage) {
        this.loginPage = loginPage;
    }
}
