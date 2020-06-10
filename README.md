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

#### 涉及处理点

处理点：1 根据请求判断是跳转登录页面还是返回JSON数据

处理点：2 用户可以配置登录页面来覆盖默认的登录页面



在src/main/resources目录下新建目录resources 并新建自定义登录页面cobra-singIn.html

配置HttpSecurity使其加载我们自定义的登录页面，.loginPage 配置的是一个静态页面

```
       http
                //表单登录设置
                .formLogin()
                 //自定义登录页面
                .loginPage("/cobra-singIn.html")
                //自定义登录请求地址默认为/login
                .loginProcessingUrl("/authentication/form")
               
```



如下所示注意这里.loginPage配置的是一个Controller而不是一个页面，这样做的好处是可以根据请求URL判断是重定向到登录页面 ，还是说直接返回JSON数据

```java
@Override
protected void configure(HttpSecurity http) throws Exception {
    http
            //表单登录设置
            .formLogin()
            //自定义登录页面，这里请求到一个Controller而不是配置的一个静态页面，好处是根据请求类型判断是否跳转页面还是返回json数据
            .loginPage("/authentication/require")
            //自定义登录请求提交地址，默认为/login
            .loginProcessingUrl("/authentication/form")
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
```



如下：同时我们增加了配置类securityProperties 在配置类中我们设置了默认跳转的登录页面，如果用户通过com.cobra.security.browser.loginPage=/demo-signIn.html 设置了自定义登录那么将覆盖我们提供的默认登录页面

```java
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
```



```java
@RestController
public class BrowserSecurityController {
    //请求缓存，可以从请求缓存中获取引发跳转的URL
    private RequestCache requestCache = new HttpSessionRequestCache();
    //由spring提供的跳转工具
    private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
    @Autowired
    private SecurityProperties securityProperties;
    @RequestMapping("/authentication/require")
    @ResponseStatus(code= HttpStatus.UNAUTHORIZED)
    public SimpleResponse requireAuthentication(HttpServletRequest request, HttpServletResponse response) throws IOException {
        //根据传入的请求获取引发跳转的请求
        SavedRequest savedRequest = requestCache.getRequest(request, response);
        if (savedRequest != null) {
            //获取引发跳转的Url
            String targetUrl = savedRequest.getRedirectUrl();
            if (targetUrl.contains(".html")) {
                redirectStrategy.sendRedirect(request, response, securityProperties.getBrowser().getLoginPage());
            }
        }
        return new SimpleResponse("访问的服务需要身份认证，请引导用户到登录页");
    }
}
```



properties的配置规划如下，放在cobra-security-core组件中

![系统配置封装](.\images\系统配置封装.png)



### 自定义登录成功处理

SpringSecurity默认是跳转到登录之前请求的URL,在登录成功处理中我们也可以加入自己的逻辑譬如登录成功加积分或者签到做记录等。

自定义登录成功处理

```java
@Component
public class CustomAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private Logger log = LoggerFactory.getLogger(CustomAuthenticationSuccessHandler.class);

    private ObjectMapper objectMapper= new ObjectMapper();

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        log.info("登录成功");
        response.setContentType("application/json;utf-8");
        response.getWriter().println(objectMapper.writeValueAsString(authentication));
    }
}
```

配置自定义登录成功处理器使其生效(这里省略了部分配置展示当前配置成功处理器的过程)

```java
@Autowired
private CustomAuthenticationSuccessHandler customAuthenticationSuccessHandler;
...
//表单登录设置
.formLogin()
//自定义登录页面，这里请求到一个Controller而不是配置的一个静态页面，好处是根据请求类型判断是否跳转页面还是返回json数据
.loginPage("/authentication/require")
//自定义登录请求提交地址，默认为/login
.loginProcessingUrl("/authentication/form")
.successHandler(customAuthenticationSuccessHandler)
...
```

### 自定义登录失败处理

可以在登录失败处理中加入失败次数统计，记录登录失败错误日志等逻辑

自定义登录失败处理器

```java
@Component("customAuthenticationFailureHandler")
public class CustomAuthenticationFailureHandler implements AuthenticationFailureHandler {

    private Logger log = LoggerFactory.getLogger(CustomAuthenticationSuccessHandler.class);

    private ObjectMapper objectMapper= new ObjectMapper();

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        log.info("登录失败");

        response.setStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
        response.setContentType("application/json;charset=utf-8");
        response.getWriter().write(objectMapper.writeValueAsString(exception));
    }
}
```

配置自定义登录失败处理器使其生效

```java

@Autowired
private CustomAuthenticationFailureHandler customAuthenticationFailureHandler;
...
//表单登录设置
.formLogin()
//自定义登录页面，这里请求到一个Controller而不是配置的一个静态页面，好处是根据请求类型判断是否跳转页面还是返回json数据
.loginPage("/authentication/require")
//自定义登录请求提交地址，默认为/login
.loginProcessingUrl("/authentication/form")
.successHandler(customAuthenticationSuccessHandler)
.failureHandler(customAuthenticationFailureHandler)
...
```

优化操作根据配置判断是返回JSON格式的数据还是跳转诱发登录前的地址

### 自定义登录成功处理器优化

SavedRequestAwareAuthenticationSuccessHandler 是SpringSecurity针对AuthenticationSuccessHandler的一个默认实现，登录成功后会跳转至引发登录前的URL，我们可以通过配置判断是返回JSON数据还是跳转至引发登录的URL，优化后的代码如下

```java
@Component("customAuthenticationSuccessHandler")
public class CustomAuthenticationSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

    @Autowired
    private SecurityProperties securityProperties;

    private Logger log = LoggerFactory.getLogger(CustomAuthenticationSuccessHandler.class);

    private ObjectMapper objectMapper= new ObjectMapper();

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        log.info("登录成功");
        if(LoginType.JSON.equals(securityProperties.getBrowser().getLoginType())){
            response.setContentType("application/json;charset=utf-8");
            response.getWriter().println(objectMapper.writeValueAsString(authentication));
        }else{
            super.onAuthenticationSuccess(request,response,authentication);
        }
    }
}
```

### 自定义登录失败处理器优化

```java
@Component("customAuthenticationFailureHandler")
public class CustomAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    @Autowired
    private SecurityProperties securityProperties;

    private Logger log = LoggerFactory.getLogger(CustomAuthenticationSuccessHandler.class);

    private ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        log.info("登录失败");
        if (LoginType.JSON.equals(securityProperties.getBrowser().getLoginType())) {
            response.setStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
            response.setContentType("application/json;charset=utf-8");
            response.getWriter().write(objectMapper.writeValueAsString(exception));
        }else{
            //注意这里登录失败是跳转到一个springboot提供的错误页面
            super.onAuthenticationFailure(request,response,exception);
        }
    }
}

```

注意这里如果是LoginType为DIRECT时，登录失败跳转到由springboot提供的一个错误页面如图所示

![自定义登录失败重定向页面效果](.\images\自定义登录失败重定向页面效果.png)



## 实现用户名+密码认证









## 实现手机号+短信认证

 





## 常见问题及解决方式

### csrf （Cross—SiteRequestForgery）

表现为如下所示：

![csrf-1](.\images\csrf-1.png)

![csrf-2](.\images\csrf-2.png)

 解决方式：//关闭跨站请求伪造csrf().disable()

  

```
  http.xxxxx.and().csrf().disable();
```

