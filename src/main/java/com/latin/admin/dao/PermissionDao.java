package com.latin.admin.dao;

import com.alibaba.fastjson.JSONObject;
import org.apache.ibatis.annotations.Mapper;

import java.util.Set;

/**
 * @author: util.you.com@gmail.com
 * @date: 2019/7/30 11:16
 * @description:
 * @version: 1.0
 * @className: PermissionDao
 */
@Mapper
public interface PermissionDao {



    /**
     * @author: util.you.com@gmail.com
     * @param: [username]
     * @return: com.alibaba.fastjson.JSONObject
     * @date: 2019/7/30 11:17
     * @version: 1.0
     * @description: 查询用户的角色 菜单 权限
     */
    JSONObject getUserPermission(String username);






    /**
     * @author: util.you.com@gmail.com
     * @param: []
     * @return: java.util.Set<java.lang.String>
     * @date: 2019/7/30 11:17
     * @version: 1.0
     * @description: 查询所有的菜单
     */
    Set<String> getAllMenu();





    /**
     * @author: util.you.com@gmail.com
     * @param: []
     * @return: java.util.Set<java.lang.String>
     * @date: 2019/7/30 11:18
     * @version: 1.0
     * @description: 查询所有的权限
     */
    Set<String> getAllPermission();
}
