package com.latin.admin.exception;

import com.alibaba.fastjson.JSONObject;
import com.latin.admin.enums.ErrorEnum;
import com.latin.admin.util.CommonUtils;
import org.springframework.boot.web.servlet.error.ErrorController;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * @author: util.you.com@gmail.com
 * @date: 2019/7/29 18:07
 * @description: 系统错误拦截，主要是针对 404 的错误
 * @version: 1.0
 * @className: MainsiteErrorController
 */
@Controller
public class MainsiteErrorController implements ErrorController {


    private static final String ERROR_PATH = "/error";





    @Override
    public String getErrorPath() {

        return ERROR_PATH;
    }






    /** 
     * @author: util.you.com@gmail.com
     * @param: []
     * @return: com.alibaba.fastjson.JSONObject
     * @date: 2019/7/29 18:10
     * @version: 1.0
     * @description:
     * 主要是登陆后的各种错误路径  404页面改为返回此json
     * 未登录的情况下,大部分接口都已经被shiro拦截,返回让用户登录了
     */
    @RequestMapping(value = ERROR_PATH)
    @ResponseBody
    public JSONObject handleError(){

        return CommonUtils.errorJson(ErrorEnum.E_501);
    }

}
