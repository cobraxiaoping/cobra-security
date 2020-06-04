package com.cobra;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class CustomUserDetailsService implements UserDetailsService {

    private Logger log = LoggerFactory.getLogger(CustomUserDetailsService.class);

    //注入在BrowserSecurityConfig类中申明的加密对象
    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        log.info("当前登录用户："+username);
        //根据用户名去数据库中查找用户
        //TODO
        //根据用户名查找用户信息,返回的是一个实现UserDetails接口的实现类,这里用springSecurity自带的一个实现Users，一般项目中需要去自己实现这个接口
        //根据查找到的用户信息判断用户是否被冻结User(String username, String password, boolean enabled,
        //			boolean accountNonExpired, boolean credentialsNonExpired,
        //			boolean accountNonLocked, Collection<? extends GrantedAuthority> authorities)
        //这里一般返回用户名以及加密后的用户密码，交给SpringSecurity做校验（从数据库读出来的密码应该是加密后的密码）
        String password = passwordEncoder.encode("123456");
        log.info("用户在数据库的密码是：" + password);
        return new User("",password, AuthorityUtils.commaSeparatedStringToAuthorityList("admin"));
    }
}
