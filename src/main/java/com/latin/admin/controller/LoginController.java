package com.latin.admin.controller;

import com.alibaba.fastjson.JSONObject;
import com.latin.admin.service.LoginService;
import com.latin.admin.util.CommonUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author: util.you.com@gmail.com
 * @date: 2019/7/30 17:17
 * @description: 登录 Controller
 * @version: 1.0
 * @className: LoginController
 */
@RestController
@RequestMapping("/login")
public class LoginController {


    // auto inject properties
    @Autowired
    private LoginService loginService;

    // add logger
    private Logger logger = LoggerFactory.getLogger(LoginController.class);



    /**
     * @author: util.you.com@gmail.com
     * @param: [requestJson]
     * @return: com.alibaba.fastjson.JSONObject
     * @date: 2019/7/30 17:22
     * @version: 1.0
     * @description: 登录
     */
    @RequestMapping("/auth")
    public JSONObject authLogin(@RequestBody JSONObject requestJson){

        CommonUtils.hasAllRequired(requestJson, "username,password");
        logger.info("---requestJson---: " + requestJson);
        JSONObject rollBackMap = loginService.authLogin(requestJson);
        logger.info("---rollBackMap----: " + rollBackMap);
        return rollBackMap;
    }






    /**
     * @author: util.you.com@gmail.com
     * @param: []
     * @return: com.alibaba.fastjson.JSONObject
     * @date: 2019/7/30 17:22
     * @version: 1.0
     * @description: 查询当前登录用户的信息
     */
    @RequestMapping("/getInfo")
    public JSONObject getInfo(){

        return loginService.getInfo();
    }





    /**
     * @author: util.you.com@gmail.com
     * @param: []
     * @return: com.alibaba.fastjson.JSONObject
     * @date: 2019/7/30 17:23
     * @version: 1.0
     * @description: 登出
     */
    @RequestMapping("/logout")
    public JSONObject logout(){

        return loginService.logout();
    }
}
