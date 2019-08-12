package com.latin.admin.dao;

import com.alibaba.fastjson.JSONObject;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import java.util.List;

/**
 * @author: util.you.com@gmail.com
 * @date: 2019/7/30 11:00
 * @description: 用户/角色/权限
 * @version: 1.0
 * @className: UserDao
 */
@Mapper
public interface UserDao {



    /**
     * @author: util.you.com@gmail.com
     * @param: [jsonObject]
     * @return: int
     * @date: 2019/7/30 11:01
     * @version: 1.0
     * @description: 查询用户数量
     */
    int countUser(JSONObject jsonObject);







    /**
     * @author: util.you.com@gmail.com
     * @param: [jsonObject]
     * @return: java.util.List<com.alibaba.fastjson.JSONObject>
     * @date: 2019/7/30 11:01
     * @version: 1.0
     * @description: 查询用户列表
     */
    List<JSONObject> listUser(JSONObject jsonObject);






    /**
     * @author: util.you.com@gmail.com
     * @param: []
     * @return: java.util.List<com.alibaba.fastjson.JSONObject>
     * @date: 2019/7/30 11:02
     * @version: 1.0
     * @description: 查询所有的角色，在添加/修改用户的时候要使用此方法
     */
    List<JSONObject> getAllRoles();






    /**
     * @author: util.you.com@gmail.com
     * @param: [jsonObject]
     * @return: int
     * @date: 2019/7/30 11:03
     * @version: 1.0
     * @description: 校验用户名是否已存在
     */
    int queryExistUsername(JSONObject jsonObject);








    /**
     * @author: util.you.com@gmail.com
     * @param:
     * @return:
     * @date: 2019/7/30 11:04
     * @version: 1.0
     * @description: 新增用户
     */
    int addUser(JSONObject jsonObject);






    /**
     * @author: util.you.com@gmail.com
     * @param: [jsonObject]
     * @return: int
     * @date: 2019/7/30 11:05
     * @version: 1.0
     * @description: 修改用户
     */
    int updateUser(JSONObject jsonObject);






    /**
     * @author: util.you.com@gmail.com
     * @param: []
     * @return: java.util.List<com.alibaba.fastjson.JSONObject>
     * @date: 2019/7/30 11:05
     * @version: 1.0
     * @description: 角色列表
     */
    List<JSONObject> listRole();







    /**
     * @author: util.you.com@gmail.com
     * @param:
     * @return:
     * @date: 2019/7/30 11:07
     * @version: 1.0
     * @description: 查询所有权限，给角色分配权限时调用
     */
    List<JSONObject> listAllPermission();







    /**
     * @author: util.you.com@gmail.com
     * @param: [jsonObject]
     * @return: int
     * @date: 2019/7/30 11:08
     * @version: 1.0
     * @description: 新增角色
     */
    int insertRole(JSONObject jsonObject);






    /**
     * @author: util.you.com@gmail.com
     * @param: [roleId, permissions] 角色 id | 权限
     * @return: int
     * @date: 2019/7/30 11:09
     * @version: 1.0
     * @description: 批量插入角色的权限
     */
    int insertRolePermission(@Param("roleId") String roleId, @Param("permissions") List<Integer> permissions);







    /**
     * @author: util.you.com@gmail.com
     * @param: [roleId, permissions]
     * @return: int
     * @date: 2019/7/30 11:11
     * @version: 1.0
     * @description: 将角色曾经拥有修改为不再拥有的权限 delete_status 改为 2
     */
    int removeOldPermission(@Param("roleId") String roleId, @Param("permissions") List<Integer> permissions);






    /**
     * @author: util.you.com@gmail.com
     * @param: [jsonObject]
     * @return: int
     * @date: 2019/7/30 11:12
     * @version: 1.0
     * @description: 修改角色名称
     */
    int updateRoleName(JSONObject jsonObject);






    /**
     * @author: util.you.com@gmail.com
     * @param: [jsonObject]
     * @return: com.alibaba.fastjson.JSONObject
     * @date: 2019/7/30 11:12
     * @version: 1.0
     * @description: 查询某角色的全部数据，在删除和修改角色时调用
     */
    JSONObject getRoleAllInfo(JSONObject jsonObject);







    /**
     * @author: util.you.com@gmail.com
     * @param: [jsonObject]
     * @return: int
     * @date: 2019/7/30 11:13
     * @version: 1.0
     * @description: 删除角色
     */
    int removeRole(JSONObject jsonObject);







    /**
     * @author: util.you.com@gmail.com
     * @param: [jsonObject]
     * @return: int
     * @date: 2019/7/30 11:13
     * @version: 1.0
     * @description: 删除本角色全部权限
     */
    int removeRoleAllPermission(JSONObject jsonObject);
}
