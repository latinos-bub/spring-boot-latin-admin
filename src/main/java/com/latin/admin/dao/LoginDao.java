package com.latin.admin.dao;

import com.alibaba.fastjson.JSONObject;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

/**
 * @author: util.you.com@gmail.com
 * @date: 2019/7/30 11:14
 * @description: 登录相关 dao
 * @version: 1.0
 * @className: LoginDao
 */
@Mapper
public interface LoginDao {



    /**
     * @author: util.you.com@gmail.com
     * @param: [username, password]
     * @return: com.alibaba.fastjson.JSONObject
     * @date: 2019/7/30 11:16
     * @version: 1.0
     * @description: 根据用户名和密码查询对应的用户
     */
    JSONObject getUser(@Param("username") String username, @Param("password") String password);
}
