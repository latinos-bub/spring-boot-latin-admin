package com.latin.admin.util;

/**
 * @author: util.you.com@gmail.com
 * @date: 2019/7/29 14:48
 * @description: 封装 String 工具类
 * @version: 1.0
 * @className: StringUtils
 */
public class StringUtils {


    /**
     * @author: util.you.com@gmail.com
     * @param: [str]
     * @return: boolean
     * @date: 2019/7/29 14:52
     * @version: 1.0
     * @description: 判断 String 是否为 Null | "" | "null"
     */
    public static boolean isNullOrEmpty(String str){

        return null == str || "".equals(str) || "null".equals(str);
    }





    /**
     * @author: util.you.com@gmail.com
     * @param: [obj]
     * @return: boolean
     * @date: 2019/7/29 14:53
     * @version: 1.0
     * @description: 判断 一个对象是否为 null || ""
     */
    public static boolean isNullOrEmpty(Object obj){

        return null == obj || "".equals(obj);
    }
}
