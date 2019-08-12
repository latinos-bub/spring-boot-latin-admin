package com.latin.admin.service.impl;

import com.alibaba.fastjson.JSONObject;
import com.latin.admin.dao.ArticleDao;
import com.latin.admin.service.ArticleService;
import com.latin.admin.util.CommonUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

/**
 * @author: util.you.com@gmail.com
 * @date: 2019/7/30 16:42
 * @description:
 * @version: 1.0
 * @className: ArticleServiceImpl
 */
@Service
public class ArticleServiceImpl implements ArticleService {


    // auto inject properties
    @Autowired(required = false)
    private ArticleDao articleDao;



    /**
     * @author: util.you.com@gmail.com
     * @param: [jsonObject]
     * @return: com.alibaba.fastjson.JSONObject
     * @date: 2019/7/30 16:44
     * @version: 1.0
     * @description: 新增文章
     */
    @Transactional(rollbackFor = Exception.class)
    @Override
    public JSONObject addArticle(JSONObject jsonObject) {

        articleDao.addArticle(jsonObject);
        return CommonUtils.successJson();
    }




    /**
     * @author: util.you.com@gmail.com
     * @param: [jsonObject]
     * @return: com.alibaba.fastjson.JSONObject
     * @date: 2019/7/30 16:45
     * @version: 1.0
     * @description: 文章列表
     */
    @Override
    public JSONObject listArticle(JSONObject jsonObject) {

        CommonUtils.fillPageParam(jsonObject);
        int count = articleDao.countArticle(jsonObject);
        List<JSONObject> list = articleDao.listArticle(jsonObject);
        return CommonUtils.successPage(jsonObject, list, count);
    }





    /**
     * @author: util.you.com@gmail.com
     * @param: [jsonObject]
     * @return: com.alibaba.fastjson.JSONObject
     * @date: 2019/7/30 16:46
     * @version: 1.0
     * @description: 更新文章
     */
    @Transactional(rollbackFor = Exception.class)
    @Override
    public JSONObject updateArticle(JSONObject jsonObject) {

        articleDao.updateArticle(jsonObject);
        return CommonUtils.successJson();
    }
}
