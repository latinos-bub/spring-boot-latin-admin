package com.latin.admin.service;

import com.alibaba.fastjson.JSONObject;

/**
 * @author: util.you.com@gmail.com
 * @date: 2019/7/30 11:21
 * @description: 用户/角色/权限
 * @version: 1.0
 * @className: UserService
 */
public interface UserService {


    /**
     * @author: util.you.com@gmail.com
     * @param: [jsonObject]
     * @return: com.alibaba.fastjson.JSONObject
     * @date: 2019/7/30 11:22
     * @version: 1.0
     * @description: 用户列表
     */
    JSONObject listUser(JSONObject jsonObject);





    /**
     * @author: util.you.com@gmail.com
     * @param: []
     * @return: com.alibaba.fastjson.JSONObject
     * @date: 2019/7/30 11:24
     * @version: 1.0
     * @description: 查询所有的角色，在添加/修改用户的时候使用此方法
     */
    JSONObject getAllRoles();





    /**
     * @author: util.you.com@gmail.com
     * @param: [jsonObject]
     * @return: com.alibaba.fastjson.JSONObject
     * @date: 2019/7/30 11:24
     * @version: 1.0
     * @description: 添加用户
     */
    JSONObject addUser(JSONObject jsonObject);





    /**
     * @author: util.you.com@gmail.com
     * @param: [jsonObject]
     * @return: com.alibaba.fastjson.JSONObject
     * @date: 2019/7/30 11:25
     * @version: 1.0
     * @description: 修改用户
     */
    JSONObject updateUser(JSONObject jsonObject);





    /**
     * @author: util.you.com@gmail.com
     * @param: []
     * @return: com.alibaba.fastjson.JSONObject
     * @date: 2019/7/30 11:25
     * @version: 1.0
     * @description: 角色列表
     */
    JSONObject listRole();





    /**
     * @author: util.you.com@gmail.com
     * @param: []
     * @return: com.alibaba.fastjson.JSONObject
     * @date: 2019/7/30 11:26
     * @version: 1.0
     * @description: 查询所有权限，给角色分配权限时调用
     */
    JSONObject listAllPermission();





    /**
     * @author: util.you.com@gmail.com
     * @param: [jsonObject]
     * @return: com.alibaba.fastjson.JSONObject
     * @date: 2019/7/30 11:26
     * @version: 1.0
     * @description: 添加角色
     */
    JSONObject addRole(JSONObject jsonObject);





    /**
     * @author: util.you.com@gmail.com
     * @param: [jsonObject]
     * @return: com.alibaba.fastjson.JSONObject
     * @date: 2019/7/30 11:27
     * @version: 1.0
     * @description: 修改角色
     */
    JSONObject updateRole(JSONObject jsonObject);







    /**
     * @author: util.you.com@gmail.com
     * @param: [jsonObject]
     * @return: com.alibaba.fastjson.JSONObject
     * @date: 2019/7/30 11:27
     * @version: 1.0
     * @description: 删除角色
     */
    JSONObject deleteRole(JSONObject jsonObject);
}
