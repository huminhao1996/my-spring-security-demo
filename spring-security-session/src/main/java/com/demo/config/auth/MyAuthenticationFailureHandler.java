package com.demo.config.auth;

import com.demo.config.exception.AjaxResponse;
import com.demo.config.exception.CustomException;
import com.demo.config.exception.CustomExceptionType;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 用户登录系统失败后 需要做的业务操作
 * extends SimpleUrlAuthenticationFailureHandler 好处是登录失败可以重新返回登录页
 * 也可以 implements AuthenticationFailureHandler
 */
@Component
public class MyAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    @Value("${spring.security.loginType}")
    private String loginType;

    private static ObjectMapper objectMapper = new ObjectMapper();

    public void onAuthenticationFailure(HttpServletRequest request,
                                        HttpServletResponse response,
                                        AuthenticationException exception)
            throws IOException, ServletException {


        if(loginType.equalsIgnoreCase("JSON")){
            response.setContentType("application/json;charset=UTF-8");
            response.getWriter().write(objectMapper.writeValueAsString(
                    AjaxResponse.error(new CustomException(
                            CustomExceptionType.USER_INPUT_ERROR,
                            "用户名或者密码输入错误!"))
            ));
        }else{
            //跳转到登陆页面
            super.onAuthenticationFailure(request,response,exception);
        }

    }
}
