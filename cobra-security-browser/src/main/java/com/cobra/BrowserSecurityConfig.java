package com.cobra;

import com.cobra.authentication.CustomAuthenticationFailureHandler;
import com.cobra.authentication.CustomAuthenticationSuccessHandler;
import com.cobra.properties.SecurityProperties;
import com.cobra.validate.code.filter.ValidateCodeFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;

import javax.sql.DataSource;

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

    @Autowired
    private DataSource dataSource;

    @Autowired
    private UserDetailsService userDetailsService;

    @Bean
    public PersistentTokenRepository persistentTokenRepository(){
        JdbcTokenRepositoryImpl jdbcTokenRepository = new JdbcTokenRepositoryImpl();
        jdbcTokenRepository.setDataSource(dataSource);
        //在项目启动的时候创建需要存储用户登录信息的表
        //jdbcTokenRepository.setCreateTableOnStartup(true);
        return jdbcTokenRepository;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        ValidateCodeFilter validateCodeFilter = new ValidateCodeFilter();
        validateCodeFilter.setAuthenticationFailureHandler(customAuthenticationFailureHandler);
        validateCodeFilter.setSecurityProperties(securityProperties);
        validateCodeFilter.afterPropertiesSet();

        http.addFilterBefore(validateCodeFilter, UsernamePasswordAuthenticationFilter.class)
                    //表单登录设置
                    .formLogin()
                    //自定义登录页面，这里请求到一个Controller而不是配置的一个静态页面，好处是根据请求类型判断是否跳转页面还是返回json数据
                    .loginPage("/authentication/require")
                    //自定义登录请求提交地址，默认为/login
                    .loginProcessingUrl("/authentication/form")
                    .successHandler(customAuthenticationSuccessHandler)
                    .failureHandler(customAuthenticationFailureHandler)
                .and()
                    .rememberMe()
                //设置用户保存token的Repository
                .tokenRepository(persistentTokenRepository())
                //设置记住我功能的有效时长单位秒这里我们做成配置可配置
                .tokenValiditySeconds(securityProperties.getBrowser().getRememberMeSeconds())
                //通过tokenRepository 中的token 获取用户名通过userDetailsService获取具体的用户信息
                .userDetailsService(userDetailsService)
                .and()
                //授权请求
                .authorizeRequests()
                //匹配上的请求放行
                .antMatchers("/authentication/require", "/code/*", securityProperties.getBrowser().getLoginPage())
                    .permitAll()
                    //未匹配上的其他请求都需要认证后才能进行访问
                    .anyRequest()
                    .authenticated()
                    //关闭跨站请求伪造
                .and().csrf().disable();
    }
}
