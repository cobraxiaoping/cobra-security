---
typora-copy-images-to: images
---

# SpringSecurity

## springSecurity核心功能  

​	 认证（你是谁）

 	授权（你能干什么）

​	攻击防护（防止伪造身份）



## SpringSecurity基本原理

```
security.basic.enabled=false
#项目中包含了springsecurity相关的依赖，默认security.basic.enabled=true（弹出窗的形式输入用户名和密码认证成功以后才会允许访问），我们可以关闭basic，如果启用了basic 认证后用户名为user(固定不变的)，密码可以从后台应用控制台查看。
```

开启basic认证后效果如下

![basic认证弹出框](.\images\basic认证弹出框.png)

![开启basic认证后的密码](.\images\开启basic认证后的密码.png)



security.basic.enabled=true和下面的配置效果一样都是启用basic认证，springsecurity的默认配置基本如下

```java
@Configuration
public class BrowserSecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.httpBasic()
                .and()
                //对请求的授权，下面的设置都是对权限的设置
                .authorizeRequests()
                .anyRequest()
                .authenticated();
    }
}
```

启用basic认证时springsecurity的过滤器链如下：（控制台日志有打印）

```java
org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter@7661b5a,
org.springframework.security.web.context.SecurityContextPersistenceFilter@29a1505c,
org.springframework.security.web.header.HeaderWriterFilter@6850b758,
org.springframework.security.web.csrf.CsrfFilter@7c251f90,
org.springframework.security.web.authentication.logout.LogoutFilter@4195105b,
org.springframework.security.web.authentication.www.BasicAuthenticationFilter@6cd5122d,
org.springframework.security.web.savedrequest.RequestCacheAwareFilter@320a8ebf,
org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter@4beabeec,
org.springframework.security.web.authentication.AnonymousAuthenticationFilter@7c36db44,
org.springframework.security.web.session.SessionManagementFilter@16e7b402,
org.springframework.security.web.access.ExceptionTranslationFilter@108a46d6,
org.springframework.security.web.access.intercept.FilterSecurityInterceptor@2b03d52f
```

更改basic认证为表单认证

```java
@Configuration
public class BrowserSecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http    
            	//指定登录方式为表单登录
                .formLogin()
                .and()
                //对请求的授权，下面的设置都是对权限的设置,所有请求都需要认证后才能访问
                .authorizeRequests()
                .anyRequest()
                .authenticated();
    }
}
```

启用表单认证时security的过滤器链如下：

```java
org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter@75483843,
org.springframework.security.web.context.SecurityContextPersistenceFilter@5b22d8a1, 
org.springframework.security.web.header.HeaderWriterFilter@44b194fe,
org.springframework.security.web.csrf.CsrfFilter@704641e3,
org.springframework.security.web.authentication.logout.LogoutFilter@4edef76c,
org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter@1894e40d,
org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter@6cd5122d,
org.springframework.security.web.savedrequest.RequestCacheAwareFilter@59ed3e6c, 
org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter@14fa92af, 
org.springframework.security.web.authentication.AnonymousAuthenticationFilter@336206d8,
org.springframework.security.web.session.SessionManagementFilter@3fe46690, 
org.springframework.security.web.access.ExceptionTranslationFilter@22e5f96e,
org.springframework.security.web.access.intercept.FilterSecurityInterceptor@7661b5a
```



两者的区别是启用basic时注册的过滤器是BasicAuthenticationFilter

启用表单登录时注册的过滤器是UsernamePasswordAuthenticationFilter

其他过滤器相同

SpringSecurity基本原理图

![springsecurity基本原理](C:\Users\Lenovo\Desktop\certs\cobra-security\images\springsecurity基本原理.png)

访问 /hello  未认证跳转/login  登录成功又跳转/hello 的跳转原理可参考如下链接的文章：

<https://blog.csdn.net/ZY_cookie/article/details/49535413>



## 自定义用户认证逻辑



### 处理用户信息获取逻辑 （UserDetailsService的实现）

```java
@Component
public class CustomUserDetailsService implements UserDetailsService {

    private Logger log = LoggerFactory.getLogger(CustomUserDetailsService.class);

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        log.info("登录用户名："+username);
        //根据用户名查找用户信息,返回的是一个实现UserDetails接口的实现类,这里用springSecurity自带的一个实现，一般项目中需要去自己实现这个接口
        return new User(username,"123456", AuthorityUtils.commaSeparatedStringToAuthorityList("admin"));
    }
}
```

### 处理用户校验逻辑（UserDetails的实现）

一，密码是否匹配

​	是由springSecurity 做的 

二，用户是否过期，是否锁定，密码是否过期，帐户是否可用等信息

​	实现UserDetails接口后需要实现如下方法告知springSecurity当前用户状态

```java
boolean isAccountNonExpired();
boolean isAccountNonLocked();
boolean isCredentialsNonExpired();
boolean isEnabled();
```

### 处理密码加密解密（PasswordEncoder的实现）

```java
package org.springframework.security.crypto.password;
public interface PasswordEncoder {
   //用户加密密码时调用的方法
   String encode(CharSequence rawPassword);
   //springSecurity校验密码是否正确时调用的方法
   boolean matches(CharSequence rawPassword, String encodedPassword);
}
```



```java
//BCryptPasswordEncoder 是SpringSecurity提供的一个PasswordEncoder的实现类，如果我们有自己的一个实现则返回自己的实现类即可，BCryptPasswordEncoder较为强大，同一密码每次加密出来的结果不一样，用到了盐的机制，推荐在项目中使用
@Bean
public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
}
```



## 个性化用户认证流程

### 自定义登录页面



### 自定义登录成功处理

SpringSecurity默认是跳转到登录之前请求的URL,在登录成功处理中我们也可以加入自己的逻辑譬如登录成功加积分或者签到做记录等。



### 自定义登录失败处理

可以在登录失败处理中加入失败次数统计，记录登录失败错误日志等逻辑







## 实现用户名+密码认证









## 实现手机号+短信认证

  	