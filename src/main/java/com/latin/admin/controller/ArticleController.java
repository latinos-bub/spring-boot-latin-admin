package com.latin.admin.controller;

import com.alibaba.fastjson.JSONObject;
import com.latin.admin.service.ArticleService;
import com.latin.admin.util.CommonUtils;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;

/**
 * @author: util.you.com@gmail.com
 * @date: 2019/7/30 17:41
 * @description: 文章 Controller
 * @version: 1.0
 * @className: ArticleController
 */
@RestController
@RequestMapping("/article")
public class ArticleController {



    // auto inject properties
    @Autowired
    private ArticleService articleService;




    /**
     * @author: util.you.com@gmail.com
     * @param: [request]
     * @return: com.alibaba.fastjson.JSONObject
     * @date: 2019/7/30 17:43
     * @version: 1.0
     * @description: 查询文章列表
     */
    @RequiresPermissions("article:list")
    @RequestMapping("/listArticle")
    public JSONObject listArticle(HttpServletRequest request){

        return articleService.listArticle(CommonUtils.request2Json(request));
    }






    /**
     * @author: util.you.com@gmail.com
     * @param: [requestJson]
     * @return: com.alibaba.fastjson.JSONObject
     * @date: 2019/7/30 18:05
     * @version: 1.0
     * @description:
     */
    @RequiresPermissions("article:add")
    @RequestMapping("/addArticle")
    public JSONObject addArticle(@RequestBody JSONObject requestJson){

        CommonUtils.hasAllRequired(requestJson, "content");
        return articleService.addArticle(requestJson);
    }





    /**
     * @author: util.you.com@gmail.com
     * @param: [requestJson]
     * @return: com.alibaba.fastjson.JSONObject
     * @date: 2019/7/30 18:07
     * @version: 1.0
     * @description:
     */
    @RequiresPermissions("article:update")
    @RequestMapping("/updateArticle")
    public JSONObject updateArticle(@RequestBody JSONObject requestJson){

        CommonUtils.hasAllRequired(requestJson, "id, content");
        return articleService.updateArticle(requestJson);
    }
}
