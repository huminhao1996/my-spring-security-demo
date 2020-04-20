package com.demo.controller;

import com.demo.config.auth.imagecode.CaptchaImageVO;
import com.google.code.kaptcha.impl.DefaultKaptcha;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.Resource;
import javax.imageio.ImageIO;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.awt.image.BufferedImage;
import java.io.IOException;

/**
 * 验证码功能
 */
@RestController
public class CaptchaController {

    @Resource
    DefaultKaptcha captchaProducer;

    /**
     * 返回验证码图片
     * @param session
     * @param response
     * @throws IOException
     */
    @RequestMapping(value="/kaptcha",method = RequestMethod.GET)
    public void kaptcha(HttpSession session, HttpServletResponse response) throws IOException {

        response.setDateHeader("Expires", 0);
        response.setHeader("Cache-Control", "no-store, no-cache, must-revalidate");
        response.addHeader("Cache-Control", "post-check=0, pre-check=0");
        response.setHeader("Pragma", "no-cache");
        response.setContentType("image/jpeg");

        //验证码文字
        String capText = captchaProducer.createText();
        //将验证码存到session
        session.setAttribute("captcha_key",
                new CaptchaImageVO(capText,2 * 60));

        //将图片返回给前端
        try(ServletOutputStream out = response.getOutputStream()){
            BufferedImage bufferedImage = captchaProducer.createImage(capText);  //生成验证码图片
            ImageIO.write(bufferedImage,"jpg",out);
            out.flush();
        }

    }


}
