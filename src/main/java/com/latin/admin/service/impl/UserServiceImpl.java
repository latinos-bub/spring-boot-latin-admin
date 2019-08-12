package com.latin.admin.service.impl;

import com.alibaba.fastjson.JSONObject;
import com.latin.admin.dao.UserDao;
import com.latin.admin.enums.ErrorEnum;
import com.latin.admin.service.UserService;
import com.latin.admin.util.CommonUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Set;

/**
 * @author: util.you.com@gmail.com
 * @date: 2019/7/30 11:34
 * @description: 用户/角色/权限
 * @version: 1.0
 * @className: UserServiceImpl
 */
@Service
public class UserServiceImpl implements UserService {


    // auto inject properties
    @Autowired(required = false)
    private UserDao userDao;



    /**
     * @author: util.you.com@gmail.com
     * @param: [jsonObject]
     * @return: com.alibaba.fastjson.JSONObject
     * @date: 2019/7/30 11:35
     * @version: 1.0
     * @description: 用户列表
     */
    @Override
    public JSONObject listUser(JSONObject jsonObject) {

        CommonUtils.fillPageParam(jsonObject);
        int count = userDao.countUser(jsonObject);
        List<JSONObject> list = userDao.listUser(jsonObject);
        return CommonUtils.successPage(jsonObject, list, count);
    }







    /**
     * @author: util.you.com@gmail.com
     * @param: []
     * @return: com.alibaba.fastjson.JSONObject
     * @date: 2019/7/30 11:49
     * @version: 1.0
     * @description: 查询所有的角色，在添加/修改用户的时候要使用此方法
     */
    @Override
    public JSONObject getAllRoles() {

        List<JSONObject> roles = userDao.getAllRoles();
        return CommonUtils.successPage(roles);
    }








    /**
     * @author: util.you.com@gmail.com
     * @param: [jsonObject]
     * @return: com.alibaba.fastjson.JSONObject
     * @date: 2019/7/30 11:45
     * @version: 1.0
     * @description: 添加用户
     */
    @Override
    public JSONObject addUser(JSONObject jsonObject) {

        int exist = userDao.queryExistUsername(jsonObject);
        if (exist > 0){
            return CommonUtils.errorJson(ErrorEnum.E_10009);
        }
        userDao.addUser(jsonObject);
        return CommonUtils.successJson();
    }







    /**
     * @author: util.you.com@gmail.com
     * @param: [jsonObject]
     * @return: com.alibaba.fastjson.JSONObject
     * @date: 2019/7/30 11:50
     * @version: 1.0
     * @description: 修改用户
     */
    @Override
    public JSONObject updateUser(JSONObject jsonObject) {

        userDao.updateUser(jsonObject);
        return CommonUtils.successJson();
    }








    /**
     * @author: util.you.com@gmail.com
     * @param: []
     * @return: com.alibaba.fastjson.JSONObject
     * @date: 2019/7/30 11:52
     * @version: 1.0
     * @description: 角色列表
     */
    @Override
    public JSONObject listRole() {

        List<JSONObject> roles = userDao.listRole();
        return CommonUtils.successPage(roles);
    }

    
    
    
    
    
    
    /** 
     * @author: util.you.com@gmail.com
     * @param: []
     * @return: com.alibaba.fastjson.JSONObject
     * @date: 2019/7/30 11:52
     * @version: 1.0
     * @description: 查询所有权限，给角色分配权限时调用
     */
    @Override
    public JSONObject listAllPermission() {

        List<JSONObject> permissions = userDao.listAllPermission();
        return CommonUtils.successPage(permissions);
    }








    /**
     * @author: util.you.com@gmail.com
     * @param: [jsonObject]
     * @return: com.alibaba.fastjson.JSONObject
     * @date: 2019/7/30 14:13
     * @version: 1.0
     * @description: 添加角色
     */
    @Transactional(rollbackFor = Exception.class)
    @SuppressWarnings("unchecked")
    @Override
    public JSONObject addRole(JSONObject jsonObject) {

        userDao.insertRole(jsonObject);
        userDao.insertRolePermission(jsonObject.getString("roleId"),
                (List<Integer>) jsonObject.get("permissions"));
        return CommonUtils.successJson();
    }






    /** 
     * @author: util.you.com@gmail.com
     * @param: [jsonObject]
     * @return: com.alibaba.fastjson.JSONObject
     * @date: 2019/7/30 14:24
     * @version: 1.0
     * @description: 修改角色
     */
    @Transactional(rollbackFor = Exception.class)
    @SuppressWarnings("unchecked")
    @Override
    public JSONObject updateRole(JSONObject jsonObject) {

        String roleId = jsonObject.getString("roleId");
        List<Integer> newPerms = (List<Integer>) jsonObject.get("permissions");
        JSONObject roleInfo = userDao.getRoleAllInfo(jsonObject);
        Set<Integer> oldPerms = (Set<Integer>) roleInfo.get("permissionIds");
        // 修改角色名称
        dealRoleName(jsonObject, roleInfo);
        // 添加新权限
        saveNewPermission(roleId, newPerms, oldPerms);
        // 移除旧的不再拥有的权限
        removeOldPermission(roleId, newPerms, oldPerms);
        return CommonUtils.successJson();
    }






    /**
     * @author: util.you.com@gmail.com
     * @param: [jsonObject]
     * @return: com.alibaba.fastjson.JSONObject
     * @date: 2019/7/30 15:21
     * @version: 1.0
     * @description: 修改角色名称
     */
    private void dealRoleName(JSONObject paramJson, JSONObject roleInfo){

        String roleName = paramJson.getString("roleName");
        if (!roleName.equals(roleInfo.getString("roleName"))){
            userDao.updateRoleName(paramJson);
        }
    }






    /**
     * @author: util.you.com@gmail.com
     * @param: []
     * @return: void
     * @date: 2019/7/30 15:23
     * @version: 1.0
     * @description: 为角色添加新权限
     */
    private void saveNewPermission(String roleId,
                                   Collection<Integer> newPerms,
                                   Collection<Integer> oldPerms){

        List<Integer> waitInsert = new ArrayList<>();
        for (Integer newPerm : newPerms){
            if (!oldPerms.contains(newPerm)){
                waitInsert.add(newPerm);
            }
        }

        if (waitInsert.size() > 0){
            userDao.insertRolePermission(roleId, waitInsert);
        }
    }







    /**
     * @author: util.you.com@gmail.com
     * @param: []
     * @return: void
     * @date: 2019/7/30 15:28
     * @version: 1.0
     * @description: 删除角色 不再拥有的权限
     */
    private void removeOldPermission(String roleId,
                                     Collection<Integer> newPerms,
                                     Collection<Integer> oldPerms){

        List<Integer> waitRemove = new ArrayList<>();
        for (Integer oldPerm : oldPerms){
            if (!newPerms.contains(oldPerm)){
                waitRemove.add(oldPerm);
            }
        }
        if (waitRemove.size() > 0){
            userDao.removeOldPermission(roleId, waitRemove);
        }
    }







    /**
     * @author: util.you.com@gmail.com
     * @param: [jsonObject]
     * @return: com.alibaba.fastjson.JSONObject
     * @date: 2019/7/30 15:32
     * @version: 1.0
     * @description: 删除角色
     */
    @Transactional(rollbackFor = Exception.class)
    @SuppressWarnings("unchecked")
    @Override
    public JSONObject deleteRole(JSONObject jsonObject) {

        JSONObject roleInfo = userDao.getRoleAllInfo(jsonObject);
        List<JSONObject> users = (List<JSONObject>) roleInfo.get("users");
        if (users != null && users.size() > 0){
            return CommonUtils.errorJson(ErrorEnum.E_10008);
        }
        userDao.removeRole(jsonObject);
        userDao.removeRoleAllPermission(jsonObject);
        return CommonUtils.successJson();
    }
}
