package com.demo.config;

import com.demo.config.auth.handler.MyAuthenticationFailureHandler;
import com.demo.config.auth.handler.MyAuthenticationSuccessHandler;
import com.demo.config.auth.handler.MyExpiredSessionStrategy;
import com.demo.config.auth.handler.MyLogoutSuccessHandler;
import com.demo.config.auth.imagecode.CaptchaCodeFilter;
import com.demo.config.auth.smscode.SmsCodeSecurityConfig;
import com.demo.config.auth.smscode.SmsCodeValidateFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.annotation.Resource;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Resource
    private MyAuthenticationSuccessHandler myAuthenticationSuccessHandler;

    @Resource
    private MyAuthenticationFailureHandler myAuthenticationFailureHandler;

    @Autowired
    private MyLogoutSuccessHandler myLogoutSuccessHandler;

    @Resource
    private CaptchaCodeFilter captchaCodeFilter;

    @Resource
    private SmsCodeValidateFilter smsCodeValidateFilter;

    @Resource
    private SmsCodeSecurityConfig smsCodeSecurityConfig; //短信认证的config

    /**
     * spring security 总体配置
     * @param http
     * @throws Exception
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable() //禁用跨站csrf攻击防御，后面的章节会专门讲解
//                .addFilterBefore(captchaCodeFilter, UsernamePasswordAuthenticationFilter.class) //放到用户名密码登录过滤器之前执行
                .addFilterBefore(smsCodeValidateFilter, UsernamePasswordAuthenticationFilter.class) //放到用户名密码登录过滤器之前执行
                .formLogin() //开始登陆配置
                .loginPage("/login.html")//用户未登录时，访问任何资源都转跳到该路径，即登录页面
                .loginProcessingUrl("/login")//登录表单form中action的地址，也就是处理认证请求的路径
                .usernameParameter("uname") //登录表单的账号参数，不修改的话默认是username
                .passwordParameter("pword") //登录表单中密码参数，不修改的话默认是password
                .successHandler(myAuthenticationSuccessHandler)
                .failureHandler(myAuthenticationFailureHandler)
                /** 不要配置defaultSuccessUrl和failureUrl，否则自定义handler将失效。handler配置与URL配置只能二选一*/
                //.defaultSuccessUrl("/index")//登录认证成功后默认转跳的路径
                //.failureUrl("/login.html") //登录认证是被跳转页面
                .and()
                    .logout() //登出配置
                    .logoutUrl("/signout") //退出的接口
    //                .logoutSuccessUrl("/aftersignout.html") //退出成功后跳转的页面
                    .deleteCookies("JSESSIONID") //删除 cookie
                    .logoutSuccessHandler(myLogoutSuccessHandler) //自定义退出成功后的处理器
                .and()
                    .apply(smsCodeSecurityConfig) //将短信认证的config 加入到主配置文件中
                .and()
                    .authorizeRequests() //权限控制
                    .antMatchers("/login.html","/login", "/kaptcha","/smscode","/smslogin")
                        .permitAll()//不需要通过登录验证就可以被访问的资源路径
                    .antMatchers("/index")
                        .authenticated() //登录后才可以访问的地址
                    .anyRequest()
                        .access("@rabcService.hasPermission(request,authentication)") //权限的具体控制
                .and()
                    .sessionManagement()//session管理
                    .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)  //默认开启session
                    .invalidSessionUrl("/login.html") //非法超时session跳转页面
                    .sessionFixation().migrateSession() //每次登录验证将创建一个新的session
                    .maximumSessions(1) //同一个用户最大的登录数量
                    .maxSessionsPreventsLogin(false) //true表示已经登录就不予许再次登录，false表示允许再次登录但是之前的登录会下线。
                    .expiredSessionStrategy(new MyExpiredSessionStrategy()); //session被下线(超时)之后的处理策略
    }

    /**
     * 用户配置
     * @param auth
     * @throws Exception
     */
    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("user")
                .password(passwordEncoder().encode("123456"))
                .roles("user")
                    .and()
                .withUser("admin")
                .password(passwordEncoder().encode("123456"))
                //.authorities("sys:log","sys:user")
                .roles("admin")
                    .and()
                .passwordEncoder(passwordEncoder());//配置BCrypt加密
    }

    /**
     * 密码编码器
     * @return
     */
    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    /**
     * 静态资源访问
     * @param web
     */
    @Override
    public void configure(WebSecurity web) {
        //将项目中静态资源路径开放出来
        web.ignoring().antMatchers( "/css/**", "/fonts/**", "/img/**", "/js/**");
    }
}
