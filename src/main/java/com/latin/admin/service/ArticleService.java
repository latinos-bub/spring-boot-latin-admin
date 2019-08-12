package com.latin.admin.service;

import com.alibaba.fastjson.JSONObject;

/**
 * @author: util.you.com@gmail.com
 * @date: 2019/7/30 11:31
 * @description:
 * @version: 1.0
 * @className: ArticleService
 */
public interface ArticleService {


    /**
     * @author: util.you.com@gmail.com
     * @param: [jsonObject]
     * @return: com.alibaba.fastjson.JSONObject
     * @date: 2019/7/30 11:32
     * @version: 1.0
     * @description: 新增文章
     */
    JSONObject addArticle(JSONObject jsonObject);




    /**
     * @author: util.you.com@gmail.com
     * @param: [jsonObject]
     * @return: com.alibaba.fastjson.JSONObject
     * @date: 2019/7/30 11:32
     * @version: 1.0
     * @description: 文章列表
     */
    JSONObject listArticle(JSONObject jsonObject);






    /**
     * @author: util.you.com@gmail.com
     * @param: [jsonObject]
     * @return: com.alibaba.fastjson.JSONObject
     * @date: 2019/7/30 11:32
     * @version: 1.0
     * @description: 更新文章
     */
    JSONObject updateArticle(JSONObject jsonObject);
}
