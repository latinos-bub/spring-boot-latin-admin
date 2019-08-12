package com.latin.admin.model;

import com.alibaba.fastjson.JSONObject;

import java.util.List;
import java.util.Set;

/**
 * @author: util.you.com@gmail.com
 * @date: 2019/7/30 10:54
 * @description: Mybatis 的一对多 JSON 返回对象
 * @version: 1.0
 * @className: One2Many
 * <p>
 *     处理嵌套查询结果时，Mybatis 会根据 bean 定义的属性类型来初始化嵌套的成员变量，
 *     主要看其是不是 Collection
 *     如果这里不定义，那么嵌套返回结果就只能返回一对一的结果，而不是一对多的
 * </p>
 */
public class One2Many extends JSONObject {

    private Set<String> roleList;


    private Set<String> menuList;


    private Set<String> permissionList;


    private Set<Integer> permissionIds;


    private List<JSONObject> picList;


    private List<JSONObject> menus;


    private List<JSONObject> users;


    private List<JSONObject> permissions;
}
