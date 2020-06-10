package com.cobra;

import com.cobra.authentication.CustomAuthenticationFailureHandler;
import com.cobra.authentication.CustomAuthenticationSuccessHandler;
import com.cobra.properties.SecurityProperties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class BrowserSecurityConfig extends WebSecurityConfigurerAdapter {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Autowired
    private SecurityProperties securityProperties;

    @Autowired
    private CustomAuthenticationSuccessHandler customAuthenticationSuccessHandler;

    @Autowired
    private CustomAuthenticationFailureHandler customAuthenticationFailureHandler;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                //表单登录设置
                .formLogin()
                //自定义登录页面，这里请求到一个Controller而不是配置的一个静态页面，好处是根据请求类型判断是否跳转页面还是返回json数据
                .loginPage("/authentication/require")
                //自定义登录请求提交地址，默认为/login
                .loginProcessingUrl("/authentication/form")
                .successHandler(customAuthenticationSuccessHandler)
                .failureHandler(customAuthenticationFailureHandler)
                .and()
                //授权请求
                .authorizeRequests()
                //匹配上的请求放行
                .antMatchers("/authentication/require", securityProperties.getBrowser().getLoginPage())
                .permitAll()
                //未匹配上的其他请求都需要认证后才能进行访问
                .anyRequest()
                .authenticated()
                //关闭跨站请求伪造
                .and().csrf().disable();
    }
}
