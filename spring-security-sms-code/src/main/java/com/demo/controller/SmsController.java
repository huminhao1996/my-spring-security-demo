package com.demo.controller;

import com.demo.config.auth.smscode.SmsCode;
import com.demo.config.exception.AjaxResponse;
import com.demo.config.exception.CustomException;
import com.demo.config.exception.CustomExceptionType;
import com.demo.dao.MyUserDetailsServiceMapper;
import com.demo.entity.MyUserDetails;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.Resource;
import javax.servlet.http.HttpSession;

@Slf4j
@RestController
public class SmsController {

    @Resource
    MyUserDetailsServiceMapper myUserDetailsServiceMapper;

    /**
     * 发送短信验证码
     * @param mobile
     * @param session
     * @return
     */
    @RequestMapping(value = "/smscode",method = RequestMethod.GET)
    public AjaxResponse sms(@RequestParam String mobile, HttpSession session){
        //查看用户手机号是否已在网站注册
        MyUserDetails myUserDetails = myUserDetailsServiceMapper.findByUserName(mobile);
        if(myUserDetails == null){
            return AjaxResponse.error(
                    new CustomException(CustomExceptionType.USER_INPUT_ERROR,
                            "您输入的手机号未曾注册")
            );
        }
        //生成四位随机号
        SmsCode smsCode = new SmsCode(RandomStringUtils.randomNumeric(4),60,mobile);
        //TODO 调用短信服务提供商的接口发送短信
        log.info(smsCode.getCode()  + "+>" + mobile);
        session.setAttribute("sms_key",smsCode);
        return AjaxResponse.success("短信验证码已经发送");
    }


}
