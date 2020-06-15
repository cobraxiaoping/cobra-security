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



## 认证流程源码级详解



![springsecurity基本原理](.\images\springsecurity基本原理-1591871809851.png)

### 认证处理流程说明

![登录流程](.\images\登录流程-1591873377064.png)

### 认证结果如何在多个请求之间共享

![认证共享](.\images\认证共享.png)

### 

```java
AbstractAuthenticationProcessingFilter.java

protected void successfulAuthentication(HttpServletRequest request,
      HttpServletResponse response, FilterChain chain, Authentication authResult)
      throws IOException, ServletException {

   if (logger.isDebugEnabled()) {
      logger.debug("Authentication success. Updating SecurityContextHolder to contain: "
            + authResult);
   }

   SecurityContextHolder.getContext().setAuthentication(authResult);

   rememberMeServices.loginSuccess(request, response, authResult);

   // Fire event
   if (this.eventPublisher != null) {
      eventPublisher.publishEvent(new InteractiveAuthenticationSuccessEvent(
            authResult, this.getClass()));
   }

   successHandler.onAuthenticationSuccess(request, response, authResult);
}
```

![spring security 过滤器链](.\images\spring security 过滤器链.png)

SecurityContextPersistenceFilter 的作用是在请求来临时从Session中获取认证信息放入SecurityContextHolder中，请求结束时将SecurityContextHolder 中的认证信息放入Session中，这样认证结果就能在多个请求之间共享。

### 获取认证用户信息



```java
@GetMapping("/me")
public Object getMe(){
    return SecurityContextHolder.getContext().getAuthentication();
}
返回数据：
{"authorities":[{"authority":"admin"}],"details":{"remoteAddress":"0:0:0:0:0:0:0:1","sessionId":"7AE4641F772EAA5F444B17A5D9D4B608"},"authenticated":true,"principal":{"password":null,"username":"22222","authorities":[{"authority":"admin"}],"accountNonExpired":true,"accountNonLocked":true,"credentialsNonExpired":true,"enabled":true},"credentials":null,"name":"22222"}
```

或者

```java
//springSecurity 会自动将SecurityContextHolder中的认证信息赋值给Authentication类型的变量
@GetMapping("/me/v1")
public Object getMeV1(Authentication authentication){
    return authentication;
}
返回数据：
{"authorities":[{"authority":"admin"}],"details":{"remoteAddress":"0:0:0:0:0:0:0:1","sessionId":"7AE4641F772EAA5F444B17A5D9D4B608"},"authenticated":true,"principal":{"password":null,"username":"22222","authorities":[{"authority":"admin"}],"accountNonExpired":true,"accountNonLocked":true,"credentialsNonExpired":true,"enabled":true},"credentials":null,"name":"22222"}
```

或者

```java
我们只关注用户的信息也可以这样
@GetMapping("/me/v2")
public Object getMeV2(@AuthenticationPrincipal UserDetails authentication){
    return authentication;
}
返回数据：
{"password":null,"username":"22222","authorities":[{"authority":"admin"}],"accountNonExpired":true,"accountNonLocked":true,"credentialsNonExpired":true,"enabled":true}
```



## 实现用户名+密码认证

### 图形验证码

图片验证码的生成步骤

1.根据随机数生成图片

2.将随机数存到Session中

3.将生成的图片写到接口的响应中

```java
@GetMapping("/code/image")
public void createCode(HttpServletRequest request, HttpServletResponse response) throws IOException {
    //第一步创建图片验证码
    ImageCode imageCode = createImageCode(request);

    //第二步将验证码放入Session中
    sessionStrategy.setAttribute(new ServletWebRequest(request), SESSION_KEY, imageCode);

    //第三步将图片验证码写入到响应中
    ImageIO.write(imageCode.getImage(), "JPEG", response.getOutputStream());
}
```

图片验证码的验证步骤

我们需要自定义filter 来验证验证码的有效性，过滤器的代码实现如下

```java
//OncePerRequestFilter 是spring 提供的一个工具类，保证过滤器只被调用一次
public class ValidateCodeFilter extends OncePerRequestFilter {

    @Autowired
    private AuthenticationFailureHandler authenticationFailureHandler;

    private SessionStrategy sessionStrategy = new HttpSessionSessionStrategy();

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        if (StringUtils.equals("/authentication/form",request.getRequestURI() ) && StringUtils.equalsIgnoreCase(request.getMethod(), "post")) {
            try {
                validate(new ServletWebRequest(request));
            } catch (ValidateCodeException e) {
                authenticationFailureHandler.onAuthenticationFailure(request, response, e);
                //如果验证码验证失败则不进行后续的过滤器处理逻辑
                return;
            }
        }
        filterChain.doFilter(request, response);
    }

    private void validate(ServletWebRequest servletWebRequest) throws ServletRequestBindingException {
        ImageCode codeInSession = (ImageCode) sessionStrategy.getAttribute(servletWebRequest, ValidateCodeController.SESSION_KEY);
        String codeInRequest = ServletRequestUtils.getStringParameter(servletWebRequest.getRequest(), "imageCode");

        if (StringUtils.isBlank(codeInRequest)) {
            throw new ValidateCodeException("验证码不能为空");
        }
        if (codeInSession == null) {
            throw new ValidateCodeException("验证码不存在");
        }
        if (codeInSession.isExpire()) {
            sessionStrategy.removeAttribute(servletWebRequest, ValidateCodeController.SESSION_KEY);
            throw new ValidateCodeException("验证码已经过期");
        }
        if (!StringUtils.equals(codeInSession.getCode(), codeInRequest)) {
            throw new ValidateCodeException("验证码不匹配");
        }
        sessionStrategy.removeAttribute(servletWebRequest, ValidateCodeController.SESSION_KEY);
    }

    public void setAuthenticationFailureHandler(AuthenticationFailureHandler authenticationFailureHandler) {
        this.authenticationFailureHandler = authenticationFailureHandler;
    }

    public void setSessionStrategy(SessionStrategy sessionStrategy) {
        this.sessionStrategy = sessionStrategy;
    }
}
```

验证不合法我们抛出自己的验证码验证异常，验证码验证异常申明如下：

```java
//AuthenticationException异常是SpringSecurity框架认证异常的基础我们基于基类申明验证码验证异常类
public class ValidateCodeException extends AuthenticationException {
    public ValidateCodeException(String msg, Throwable t) {
        super(msg, t);
    }

    public ValidateCodeException(String msg) {
        super(msg);
    }
}
```



在我们申明了图片验证码过滤器时我们需要将过滤器加入到过滤器链中，我们放在UsernamePasswordAuthenticationFilter过滤器前完成图片验证码的验证

```java
...
ValidateCodeFilter validateCodeFilter = new ValidateCodeFilter();
validateCodeFilter.setAuthenticationFailureHandler(customAuthenticationFailureHandler);

http.addFilterBefore(validateCodeFilter, UsernamePasswordAuthenticationFilter.class)
...
```

### 重构图形验证码

验证码基本参数可配

![图形验证码基本参数配置](.\images\图形验证码基本参数配置.png)

请求级别配置

```html
<tr>
    <td>图形验证码</td>
    <td><input type="text" name="imageCode">
        <img src="/code/image?width=200">
    </td>
</tr>
```

应用级别配置

```java
#应用级别配置图形验证码的长度
com.cobra.security.code.image.width=100
```

默认级别配置，默认是类中默认的长度如下：

```java
...
//图形验证码的默认长度
private int width=67;
//图形验证码的默认高度
private int height=23;
...
```

```java
int width = ServletRequestUtils.getIntParameter(request.getRequest(),"width",securityProperties.getCode().getImage().getWidth());
```



验证码拦截接口可配置



验证码的生成逻辑可配置

定义验证码生成接口

```java
public interface ValidateCodeGenerator {
     ImageCode createImageCode(ServletWebRequest request);
}
```



提供一个默认实现

```java
public class DefaultValidateCodeGenerator implements ValidateCodeGenerator{

    public SecurityProperties securityProperties;

    @Override
    public ImageCode createImageCode(ServletWebRequest request) {
        int width = ServletRequestUtils.getIntParameter(request.getRequest(),"width",securityProperties.getCode().getImage().getWidth());
        int height =ServletRequestUtils.getIntParameter(request.getRequest(),"height", securityProperties.getCode().getImage().getHeight());
        BufferedImage image = new BufferedImage(width, height, BufferedImage.TYPE_INT_RGB);

        Graphics g = image.getGraphics();

        Random random = new Random();

        g.setColor(getRandColor(200, 250));
        g.fillRect(0, 0, width, height);
        g.setFont(new Font("Times New Roman", Font.ITALIC, 20));
        g.setColor(getRandColor(160, 200));
        for (int i = 0; i < 155; i++) {
            int x = random.nextInt(width);
            int y = random.nextInt(height);
            int xl = random.nextInt(12);
            int yl = random.nextInt(12);
            g.drawLine(x, y, x + xl, y + yl);
        }

        String sRand = "";
        for (int i = 0; i < securityProperties.getCode().getImage().getLength(); i++) {
            String rand = String.valueOf(random.nextInt(10));
            sRand += rand;
            g.setColor(new Color(20 + random.nextInt(110), 20 + random.nextInt(110), 20 + random.nextInt(110)));
            g.drawString(rand, 13 * i + 6, 16);
        }
        g.dispose();
        return new ImageCode(image, sRand, securityProperties.getCode().getImage().getExpireIn());
    }

    private Color getRandColor(int fc, int bc) {
        Random random = new Random();
        if (fc > 255) {
            fc = 255;
        }
        if (bc > 255) {
            bc = 255;
        }
        int r = fc + random.nextInt(bc - fc);
        int g = fc + random.nextInt(bc - fc);
        int b = fc + random.nextInt(bc - fc);
        return new Color(r, g, b);
    }

    public SecurityProperties getSecurityProperties() {
        return securityProperties;
    }

    public void setSecurityProperties(SecurityProperties securityProperties) {
        this.securityProperties = securityProperties;
    }
}
```



使默认配置生效

```java
@Configuration
public class ValidateCodeBeanConfig {

    @Autowired
    private SecurityProperties securityProperties;


    /**
     * 注意这里用了一个注解@ConditionalOnMissingBean 在应用启动的时候会先去容器中查找名为imageValidateCodeGenerator的bean如果没有查找到则创建默认的生成逻辑
     * */
    @Bean
    @ConditionalOnMissingBean(name="imageValidateCodeGenerator")
    public ValidateCodeGenerator imageValidateCodeGenerator(){
        DefaultValidateCodeGenerator validateCodeGenerator = new DefaultValidateCodeGenerator();
        validateCodeGenerator.setSecurityProperties(securityProperties);
        return  validateCodeGenerator;
    }
}
```



如果需要覆盖默认的生成逻辑只需要实现我们提供的ValidateCodeGenerator接口

样例如下：

```java
@Component("imageValidateCodeGenerator")
public class DemoImageCodeGenerator implements ValidateCodeGenerator {
    @Override
    public ImageCode createImageCode(ServletWebRequest request) {
        System.out.println("更高级的图形验证码生成");
        return null;
    }
}
```



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

