package com.cobra;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class BrowserSecurityConfig extends WebSecurityConfigurerAdapter {

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                //表单登录设置
                .formLogin()
                .loginPage("/cobra-singIn.html")
                .and()
                //授权请求
                .authorizeRequests()
                //匹配上的请求放行
                .antMatchers("/cobra-singIn.html")
                .permitAll()
                //未匹配上的其他请求都需要认证后才能进行访问
                .anyRequest()
                .authenticated();
    }
}
