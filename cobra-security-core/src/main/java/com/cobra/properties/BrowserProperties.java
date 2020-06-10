package com.cobra.properties;

import com.cobra.enums.LoginType;

public class BrowserProperties {
    //设置默认登录页面，如果配置了com.cobra.security.browser.loginPage 则会覆盖默认登录页面
    private String loginPage = "/default-singIn.html";

    //设置登录成功或者失败时是返回json数据格式 还是重定向操作，这里默认返回JSON
    private LoginType loginType = LoginType.JSON;

    public String getLoginPage() {
        return loginPage;
    }

    public void setLoginPage(String loginPage) {
        this.loginPage = loginPage;
    }

    public LoginType getLoginType() {
        return loginType;
    }

    public void setLoginType(LoginType loginType) {
        this.loginType = loginType;
    }
}
