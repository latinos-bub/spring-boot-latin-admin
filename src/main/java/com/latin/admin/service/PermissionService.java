package com.latin.admin.service;

import com.alibaba.fastjson.JSONObject;

/**
 * @author: util.you.com@gmail.com
 * @date: 2019/7/30 11:28
 * @description:
 * @version: 1.0
 * @className: PermissionService
 */
public interface PermissionService {


    /**
     * @author: util.you.com@gmail.com
     * @param: [username]
     * @return: com.alibaba.fastjson.JSONObject
     * @date: 2019/7/30 11:29
     * @version: 1.0
     * @description: 查询某用户的角色、菜单列表、权限列表
     */
    JSONObject getUserPermission(String username);
}
