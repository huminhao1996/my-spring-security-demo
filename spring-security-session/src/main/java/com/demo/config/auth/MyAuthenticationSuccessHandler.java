package com.demo.config.auth;

import com.demo.config.exception.AjaxResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 登录成功后的 处理器
 * 处理 用户登录成功后需要做的业务操作
 * SavedRequestAwareAuthenticationSuccessHandler 继承至 SimpleUrlAuthenticationSuccessHandler
 * SimpleUrlAuthenticationSuccessHandler 实现了 AuthenticationSuccessHandler接口
 */
@Component
public class MyAuthenticationSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

    @Value("${spring.security.loginType}")
    private String loginType;

    private static ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication)
            throws ServletException, IOException {

        if(loginType.equalsIgnoreCase("JSON")){
            response.setContentType("application/json;charset=UTF-8");
            response.getWriter().write(objectMapper.writeValueAsString(
                    AjaxResponse.success("/index")
            ));
        }else{
            //跳转到登陆之前请求的页面 前后端一体的情况下
            super.onAuthenticationSuccess(request,response,authentication);
        }


    }
}
