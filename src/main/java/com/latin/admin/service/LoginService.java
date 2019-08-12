package com.latin.admin.service;

import com.alibaba.fastjson.JSONObject;

/**
 * @author: util.you.com@gmail.com
 * @date: 2019/7/29 16:21
 * @description: 登录 Service
 * @version: 1.0
 * @className: LoginService
 */
public interface LoginService {



    /**
     * @author: util.you.com@gmail.com
     * @param: [jsonObject]
     * @return: com.alibaba.fastjson.JSONObject
     * @date: 2019/7/29 16:22
     * @version: 1.0
     * @description: 登录表单提交
     */
    JSONObject authLogin(JSONObject jsonObject);






    /**
     * @author: util.you.com@gmail.com
     * @param: [userName, passWord]
     * @return: com.alibaba.fastjson.JSONObject
     * @date: 2019/7/29 16:22
     * @version: 1.0
     * @description: 根据用户名和密码查询对应的用户
     */
    JSONObject getUser(String userName, String passWord);








    /**
     * @author: util.you.com@gmail.com
     * @param: []
     * @return: com.alibaba.fastjson.JSONObject
     * @date: 2019/7/29 16:23
     * @version: 1.0
     * @description: 查询当前登录用户的权限等信息
     */
    JSONObject getInfo();






    /**
     * @author: util.you.com@gmail.com
     * @param: []
     * @return: com.alibaba.fastjson.JSONObject
     * @date: 2019/7/29 16:23
     * @version: 1.0
     * @description: 退出登录
     */
    JSONObject logout();
}
