package com.latin.admin.service.impl;

import com.alibaba.fastjson.JSONObject;
import com.latin.admin.dao.LoginDao;
import com.latin.admin.enums.ErrorEnum;
import com.latin.admin.service.LoginService;
import com.latin.admin.service.PermissionService;
import com.latin.admin.util.CommonUtils;
import com.latin.admin.util.ConstantUtils;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import org.apache.shiro.subject.Subject;

import org.apache.shiro.session.Session;
import org.springframework.stereotype.Service;

/**
 * @author: util.you.com@gmail.com
 * @date: 2019/7/30 15:37
 * @description:
 * @version: 1.0
 * @className: LoginServiceImpl
 */
@Service
public class LoginServiceImpl implements LoginService {


    // auto inject properties
    @Autowired(required = false)
    private LoginDao loginDao;


    @Autowired(required = false)
    private PermissionService permissionService;


    // add logger
    private Logger logger = LoggerFactory.getLogger(LoginServiceImpl.class);



    /**
     * @author: util.you.com@gmail.com
     * @param: [jsonObject]
     * @return: com.alibaba.fastjson.JSONObject
     * @date: 2019/7/30 15:45
     * @version: 1.0
     * @description: 登录表单提交
     */
    @Override
    public JSONObject authLogin(JSONObject jsonObject) {

        String username = jsonObject.getString("username");
        String password = jsonObject.getString("password");
        JSONObject info = new JSONObject();
        Subject currentUser = SecurityUtils.getSubject();
        UsernamePasswordToken token = new UsernamePasswordToken(username, password);
        try {
            logger.info("---token---: " + token);
            currentUser.login(token);
            info.put("result", "success");
        }catch (UnknownAccountException e){
            logger.error(String.format("用户不存在: %s", username), e);
            info.put("result", "fail");
        }catch (IncorrectCredentialsException e){
            logger.error(String.format("密码不正确: %s", username), e);
            info.put("result", "fail" +
                    "");
        }catch (ConcurrentAccessException e){
            logger.error(String.format("用户重复登录: %s", username), e);
            info.put("result", "fail");
        }catch (AccountException e){
            logger.error(String.format("其他账户异常: %s", username), e);
            info.put("result", "fail");
        }
        return info;
    }





    /**
     * @author: util.you.com@gmail.com
     * @param: [userName, passWord]
     * @return: com.alibaba.fastjson.JSONObject
     * @date: 2019/7/30 15:45
     * @version: 1.0
     * @description: 根据用户名和密码查询对应的用户
     */
    @Override
    public JSONObject getUser(String userName, String passWord) {

        return loginDao.getUser(userName, passWord);
    }






    /**
     * @author: util.you.com@gmail.com
     * @param: []
     * @return: com.alibaba.fastjson.JSONObject
     * @date: 2019/7/30 15:46
     * @version: 1.0
     * @description: 查询当前登录用户的权限等信息
     */
    @Override
    public JSONObject getInfo() {

        // 从 Session 中获取用于信息
        Session session = SecurityUtils.getSubject().getSession();
        JSONObject userInfo = (JSONObject) session.getAttribute(ConstantUtils.SESSION_USER_INFO);
        String userName = userInfo.getString("username");
        JSONObject info = new JSONObject();
        JSONObject userPermission = permissionService.getUserPermission(userName);
        session.setAttribute(ConstantUtils.SESSION_USER_PERMISSION, userPermission);
        info.put("userPermission", userPermission);
        return CommonUtils.successJson(info);
    }








    /**
     * @author: util.you.com@gmail.com
     * @param: []
     * @return: com.alibaba.fastjson.JSONObject
     * @date: 2019/7/30 15:52
     * @version: 1.0
     * @description: 退出登录
     */
    @Override
    public JSONObject logout() {

        try {
            Subject currentUser = SecurityUtils.getSubject();
            currentUser.logout();
        }catch (Exception e){
            return CommonUtils.errorJson(ErrorEnum.E_400);
        }
        return CommonUtils.successJson();
    }
}
