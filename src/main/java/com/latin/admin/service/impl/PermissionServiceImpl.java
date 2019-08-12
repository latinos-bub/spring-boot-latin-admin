package com.latin.admin.service.impl;

import com.alibaba.fastjson.JSONObject;
import com.latin.admin.dao.PermissionDao;
import com.latin.admin.service.PermissionService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Set;

/**
 * @author: util.you.com@gmail.com
 * @date: 2019/7/30 15:55
 * @description:
 * @version: 1.0
 * @className: PermissionServiceImpl
 */
@Service
public class PermissionServiceImpl implements PermissionService {


    // auto inject properties
    @Autowired(required = false)
    private PermissionDao permissionDao;



    /**
     * @author: util.you.com@gmail.com
     * @param: [username]
     * @return: com.alibaba.fastjson.JSONObject
     * @date: 2019/7/30 15:56
     * @version: 1.0
     * @description: 查询某用户的角色、菜单列表、权限列表
     */
    @Override
    public JSONObject getUserPermission(String userName) {

        JSONObject userPermission = getUserPermissionFromDB(userName);
        return userPermission;
    }







    /**
     * @author: util.you.com@gmail.com
     * @param: [userName]
     * @return: com.alibaba.fastjson.JSONObject
     * @date: 2019/7/30 15:57
     * @version: 1.0
     * @description: 从数据库查询用户权限信息
     */
    private JSONObject getUserPermissionFromDB(String userName){

        JSONObject userPermission = permissionDao.getUserPermission(userName);
        // 管理员角色 id 为1
        int adminRoleId = 1;
        // 若是管理员
        String roleIdKey = "roleId";
        if (adminRoleId == userPermission.getIntValue(roleIdKey)){
            // 查询所有菜单 所有权限
            Set<String> menuList = permissionDao.getAllMenu();
            Set<String> permissionList = permissionDao.getAllPermission();
            userPermission.put("menuList", menuList);
            userPermission.put("permissionList", permissionList);
        }
        return userPermission;
    }
}
