package com.demo.config.auth.imagecode;

import java.time.LocalDateTime;

/**
 * 验证码 VO
 */
public class CaptchaImageVO {

    private String code;

    private LocalDateTime expireTime;


    public CaptchaImageVO(String code,int expireAfterSeconds){
        this.code = code;
        this.expireTime = LocalDateTime.now().plusSeconds(expireAfterSeconds);
    }

    public String getCode() {
        return code;
    }

    /**
     * 验证码是否失效
     * @return
     */
    public boolean isExpired(){
        return  LocalDateTime.now().isAfter(expireTime);
    }
}
