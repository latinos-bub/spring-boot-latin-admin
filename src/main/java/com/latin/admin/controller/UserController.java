package com.latin.admin.controller;

import com.alibaba.fastjson.JSONObject;
import com.latin.admin.service.UserService;
import com.latin.admin.util.CommonUtils;
import org.apache.shiro.authz.annotation.Logical;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;

/**
 * @author: util.you.com@gmail.com
 * @date: 2019/7/30 17:24
 * @description: 用户/角色/权限相关 Controller
 * @version: 1.0
 * @className: UserController
 */
@RestController
@RequestMapping("/user")
public class UserController {


    // auto inject properties
    @Autowired
    private UserService userService;



    /**
     * @author: util.you.com@gmail.com
     * @param: []
     * @return: com.alibaba.fastjson.JSONObject
     * @date: 2019/7/30 17:25
     * @version: 1.0
     * @description: 查询用户列表
     */
    @RequiresPermissions("user:list")
    @RequestMapping("/list")
    public JSONObject listUser(HttpServletRequest request){

        return userService.listUser(CommonUtils.request2Json(request));
    }





    /**
     * @author: util.you.com@gmail.com
     * @param: [requestJson]
     * @return: com.alibaba.fastjson.JSONObject
     * @date: 2019/7/30 17:31
     * @version: 1.0
     * @description: 添加用户
     */
    @RequiresPermissions("user:add")
    @RequestMapping("/addUser")
    public JSONObject addUser(@RequestBody JSONObject requestJson){

        CommonUtils.hasAllRequired(requestJson, "username, password, nickname, roleId");
        return userService.addUser(requestJson);
    }






    /**
     * @author: util.you.com@gmail.com
     * @param: [requestJson]
     * @return: com.alibaba.fastjson.JSONObject
     * @date: 2019/7/30 17:37
     * @version: 1.0
     * @description:
     */
    @RequiresPermissions("user:update")
    @RequestMapping("/updateUser")
    public JSONObject updateUser(@RequestBody JSONObject requestJson){

        CommonUtils.hasAllRequired(requestJson, "nickname, roleId, deleteStatus, userId");
        return userService.updateUser(requestJson);
    }







    /**
     * @author: util.you.com@gmail.com
     * @param: []
     * @return: com.alibaba.fastjson.JSONObject
     * @date: 2019/7/30 17:39
     * @version: 1.0
     * @description:
     */
    @RequiresPermissions(value = {"user:add", "user:update"}, logical = Logical.OR)
    @RequestMapping("/getAllRoles")
    public JSONObject getAllRoles() {

        return userService.getAllRoles();
    }





    /**
     * @author: util.you.com@gmail.com
     * @param: []
     * @return: com.alibaba.fastjson.JSONObject
     * @date: 2019/7/30 17:39
     * @version: 1.0
     * @description: 角色列表
     */
    @RequiresPermissions("role:list")
    @RequestMapping("/listRole")
    public JSONObject listRole() {

        return userService.listRole();
    }






    /**
     * @author: util.you.com@gmail.com
     * @param: []
     * @return: com.alibaba.fastjson.JSONObject
     * @date: 2019/7/30 17:40
     * @version: 1.0
     * @description: 查询所有权限, 给角色分配权限时调用
     */
    @RequiresPermissions("role:list")
    @RequestMapping("/listAllPermission")
    public JSONObject listAllPermission() {

        return userService.listAllPermission();
    }






    /**
     * @author: util.you.com@gmail.com
     * @param: [requestJson]
     * @return: com.alibaba.fastjson.JSONObject
     * @date: 2019/7/30 17:40
     * @version: 1.0
     * @description: 新增角色
     */
    @RequiresPermissions("role:add")
    @RequestMapping("/addRole")
    public JSONObject addRole(@RequestBody JSONObject requestJson) {

        CommonUtils.hasAllRequired(requestJson, "roleName,permissions");
        return userService.addRole(requestJson);
    }







    /**
     * @author: util.you.com@gmail.com
     * @param: [requestJson]
     * @return: com.alibaba.fastjson.JSONObject
     * @date: 2019/7/30 17:40
     * @version: 1.0
     * @description: 修改角色
     */
    @RequiresPermissions("role:update")
    @RequestMapping("/updateRole")
    public JSONObject updateRole(@RequestBody JSONObject requestJson) {

        CommonUtils.hasAllRequired(requestJson, "roleId,roleName,permissions");
        return userService.updateRole(requestJson);
    }






    /**
     * @author: util.you.com@gmail.com
     * @param: [requestJson]
     * @return: com.alibaba.fastjson.JSONObject
     * @date: 2019/7/30 17:40
     * @version: 1.0
     * @description: 删除角色
     */
    @RequiresPermissions("role:delete")
    @RequestMapping("/deleteRole")
    public JSONObject deleteRole(@RequestBody JSONObject requestJson) {

        CommonUtils.hasAllRequired(requestJson, "roleId");
        return userService.deleteRole(requestJson);
    }

}
