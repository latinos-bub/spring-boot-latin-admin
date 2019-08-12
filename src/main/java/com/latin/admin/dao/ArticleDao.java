package com.latin.admin.dao;

import com.alibaba.fastjson.JSONObject;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;

/**
 * @author: util.you.com@gmail.com
 * @date: 2019/7/30 11:18
 * @description: 文章 dao
 * @version: 1.0
 * @className: ArticleDao
 */
@Mapper
public interface ArticleDao {


    /**
     * @author: util.you.com@gmail.com
     * @param: [jsonObject]
     * @return: int
     * @date: 2019/7/30 11:19
     * @version: 1.0
     * @description: 新增文章
     */
    int addArticle(JSONObject jsonObject);






    /**
     * @author: util.you.com@gmail.com
     * @param: [jsonObject]
     * @return: int
     * @date: 2019/7/30 11:19
     * @version: 1.0
     * @description: 统计文章总数
     */
    int countArticle(JSONObject jsonObject);





    /**
     * @author: util.you.com@gmail.com
     * @param: [jsonObject]
     * @return: java.util.List<com.alibaba.fastjson.JSONObject>
     * @date: 2019/7/30 11:20
     * @version: 1.0
     * @description: 文章列表
     */
    List<JSONObject> listArticle(JSONObject jsonObject);






    /**
     * @author: util.you.com@gmail.com
     * @param: [jsonObject]
     * @return: int
     * @date: 2019/7/30 11:20
     * @version: 1.0
     * @description: 更新文章
     */
    int updateArticle(JSONObject jsonObject);
}
