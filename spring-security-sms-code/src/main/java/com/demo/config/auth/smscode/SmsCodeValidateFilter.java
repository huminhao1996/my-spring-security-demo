package com.demo.config.auth.smscode;

import com.demo.config.auth.handler.MyAuthenticationFailureHandler;
import com.demo.constant.SecurityContants;
import com.demo.dao.MyUserDetailsServiceMapper;
import com.demo.entity.MyUserDetails;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.ServletRequestBindingException;
import org.springframework.web.bind.ServletRequestUtils;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.annotation.Resource;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.Objects;

/**
 * 校验短信验证码是否正确的过滤器
 */
@Component
public class SmsCodeValidateFilter extends OncePerRequestFilter {

    @Resource
    MyUserDetailsServiceMapper myUserDetailsServiceMapper;

    @Resource
    MyAuthenticationFailureHandler myAuthenticationFailureHandler;

    /**
     * 短信验证
     * @param request
     * @param response
     * @param filterChain
     * @throws ServletException
     * @throws IOException
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {
        if(StringUtils.equals("/smslogin",request.getRequestURI())
                && StringUtils.equalsIgnoreCase(request.getMethod(),"post")){

            try{
                //验证谜底与用户输入是否匹配
                validate(new ServletWebRequest(request));
            }catch(AuthenticationException e){
                myAuthenticationFailureHandler.onAuthenticationFailure(
                        request,response,e
                );
                return;
            }

        }

        filterChain.doFilter(request,response);

    }

    //短信验证 具体方法
    private void validate(ServletWebRequest request) throws ServletRequestBindingException {

        HttpSession session = request.getRequest().getSession();
        SmsCode codeInSession = (SmsCode)session.getAttribute(SecurityContants.SMS_SESSION_KEY);
        String mobileInRequest = request.getParameter("mobile");
        String codeInRequest = request.getParameter("smsCode");

        if(StringUtils.isEmpty(mobileInRequest)){
            throw new SessionAuthenticationException("手机号码不能为空");
        }

        if(StringUtils.isEmpty(codeInRequest)) {
            throw new SessionAuthenticationException("短信验证码不能为空");
        }

        if(Objects.isNull(codeInSession)) {
            throw new SessionAuthenticationException("短信验证码不存在");
        }

        if(codeInSession.isExpired()) {
            session.removeAttribute(SecurityContants.SMS_SESSION_KEY);
            throw new SessionAuthenticationException("短信验证码已经过期");
        }

        if(!codeInSession.getCode().equals(codeInRequest)) {
            throw new SessionAuthenticationException("短信验证码不正确");
        }

        if(!codeInSession.getMobile().equals(mobileInRequest)) {
            throw new SessionAuthenticationException("短信发送目标与您输入的手机号不一致");
        }

        MyUserDetails myUserDetails = myUserDetailsServiceMapper.findByUserName(mobileInRequest);
        if(Objects.isNull(myUserDetails)){
            throw new SessionAuthenticationException("您输入的手机号不是系统的注册用户");
        }

        session.removeAttribute(SecurityContants.SMS_SESSION_KEY);

    }
}
