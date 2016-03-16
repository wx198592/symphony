/*
 * Copyright (c) 2012-2016, b3log.org & hacpai.com
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.b3log.symphony.processor;
import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.RandomStringUtils;
import org.apache.commons.lang.time.DateUtils;
import org.b3log.latke.Keys;
import org.b3log.latke.logging.Level;
import org.b3log.latke.logging.Logger;
import org.b3log.latke.model.Role;
import org.b3log.latke.model.User;
import org.b3log.latke.service.LangPropsService;
import org.b3log.latke.service.ServiceException;
import org.b3log.latke.servlet.HTTPRequestContext;
import org.b3log.latke.servlet.HTTPRequestMethod;
import org.b3log.latke.servlet.annotation.Before;
import org.b3log.latke.servlet.annotation.RequestProcessing;
import org.b3log.latke.servlet.annotation.RequestProcessor;
import org.b3log.latke.util.MD5;
import org.b3log.latke.util.Requests;
import org.b3log.latke.util.Strings;
import org.b3log.symphony.model.Common;
import org.b3log.symphony.model.UserExt;
import org.b3log.symphony.model.Verifycode;
import org.b3log.symphony.model.Vote;
import org.b3log.symphony.service.UserMgmtService;
import org.b3log.symphony.service.UserQueryService;
import org.b3log.symphony.service.VerifycodeMgmtService;
import org.b3log.symphony.util.Dingding;
import org.json.JSONArray;
import org.json.JSONObject;

import java.util.Date;
import java.util.ResourceBundle;

/**
 * Created by weixing on 16/3/10.
 */
@RequestProcessor
public class ThirdPartyAuth {

    /**
     * Logger.
     */
    private static final Logger LOGGER = Logger.getLogger(ThirdPartyAuth.class.getName());


    /**
     * Language service.
     */
    @Inject
    private LangPropsService langPropsService;

    /**
     * User management service.
     */
    @Inject
    private UserMgmtService userMgmtService;

    /**
     * User query service.
     */
    @Inject
    private UserQueryService userQueryService;

    /**
     * Verifycode management service.
     */
    @Inject
    private VerifycodeMgmtService verifycodeMgmtService;

    /**
     * Votes up an article.
     * <p>
     * <p>
     * The request json object:
     * <pre>
     * {
     *   "dataId": ""
     * }
     * </pre>
     * </p>
     *
     * @param context  the specified context
     * @param request  the specified request
     * @param response the specified response
     * @throws Exception exception
     */
    @RequestProcessing(value = "/thirdPartyAuth", method = HTTPRequestMethod.POST)
    public void getAuthKey(final HTTPRequestContext context, final HttpServletRequest request,
                           final HttpServletResponse response) throws Exception {
        context.renderJSON();

        final JSONObject requestJSONObject = Requests.parseRequestJSONObject(request, context.getResponse());
        final String userDelegateId = requestJSONObject.optString(Common.THIRD_PARTY_USER_ID);
        final String userName = requestJSONObject.optString(Common.THIRD_PARTY_USER_NAME);
        final String userFrom = requestJSONObject.optString(Common.THIRD_PARTY_USER_FROM);
        final String userCompanyId = requestJSONObject.optString(Common.THIRD_PARTY_COMPANY_ID);

        String userEmail = userDelegateId + "@default.com";
//        final String userIcon = requestJSONObject.optString(Common.THIRD_PARTY_USER_ICON);
        LOGGER.info(requestJSONObject.toString());

        String code = RandomStringUtils.randomAlphanumeric(15);

        JSONObject user = userQueryService.getUserByDelegateIdAndCompanyId(userDelegateId, userCompanyId);
        String userId4Verify = "";

        if( user == null) {
            user = new JSONObject();
            user.put(User.USER_NAME, userName);
            user.put(User.USER_EMAIL, userEmail);
            user.put(User.USER_PASSWORD, "");
            user.put(UserExt.USER_FROM, userFrom);
            user.put(UserExt.USER_DELEGATE_ID, userDelegateId);
            user.put(UserExt.USER_THIRD_PARTY_COMPANY_ID, userCompanyId);
//            user.put(UserExt.USER_THIRD_PARTY_KEY, code);
            user.put(UserExt.USER_STATUS, UserExt.USER_STATUS_C_VALID);
//            user.put(UserExt.USER_AVATAR_URL, userIcon);


            try {
                final String newUserId = userMgmtService.addUser(user);
                userId4Verify = newUserId;
            } catch (final ServiceException e) {
                final String msg = langPropsService.get("registerFailLabel") + " - " + e.getMessage();
                LOGGER.log(Level.ERROR, msg + "[name={0}]", userName);

                context.renderMsg(msg);
            }

        } else {
            userId4Verify = user.optString(Keys.OBJECT_ID);
//            user.put(UserExt.USER_THIRD_PARTY_KEY, code);
//            userMgmtService.updateThirdPartyKey(user);
        }

        //添加verify code
        final JSONObject verifycode = new JSONObject();
        verifycode.put(Verifycode.BIZ_TYPE, Verifycode.BIZ_TYPE_C_THIRD_PARTY_REGISTER);
        verifycode.put(Verifycode.CODE, code);
        verifycode.put(Verifycode.EXPIRED, DateUtils.addSeconds(new Date(), 10).getTime());
        verifycode.put(Verifycode.RECEIVER, userEmail);
        verifycode.put(Verifycode.STATUS, Verifycode.STATUS_C_UNSENT);
        verifycode.put(Verifycode.TYPE, Verifycode.TYPE_C_THIRD_PARTY);
        verifycode.put(Verifycode.USER_ID, userId4Verify);
        verifycodeMgmtService.addVerifycode(verifycode);

        context.renderTrueResult().renderJSONValue(Common.THIRD_PARTY_KEY, code);
    }


    @RequestProcessing(value = "/configureAdmins", method = HTTPRequestMethod.POST)
    public void configureAdmins(final HTTPRequestContext context, final HttpServletRequest request,
                           final HttpServletResponse response) throws Exception {

        final JSONObject requestJSONObject = Requests.parseRequestJSONObject(request, context.getResponse());
        String userFrom = request.getParameter(Common.THIRD_PARTY_USER_FROM);

        //配置钉钉管理员
        if(userFrom.equals(Dingding.DING_DING)) {
            final JSONArray admins = requestJSONObject.optJSONArray(Common.THIRD_PARTY_CONFIG_ADMINS);
            for(int i = 0; i < admins.length(); i++) {
                JSONObject admin = (JSONObject)admins.get(i);
                LOGGER.info(admin.toString());
                //获取admin 的 delegateId companyId name
                final String userDelegateId = admin.optString(Common.THIRD_PARTY_USER_ID);
                final String userName = admin.optString(Common.THIRD_PARTY_USER_NAME);
                final String userCompanyId = admin.optString(Common.THIRD_PARTY_COMPANY_ID);
                final String configAction = admin.optString(Common.THIRD_PARTY_CONFIG_ADMINS_ACTION);

                JSONObject user = userQueryService.getUserByDelegateIdAndCompanyId(userDelegateId, userCompanyId);

                // delete
                if(configAction.equals("delete".toString())) {
                    JSONObject userDel = user;
                    if(userDel == null) {
                        continue;
                    } else {
                        userMgmtService.removeUser(user.optString(Keys.OBJECT_ID));
                    }
                } else if(configAction.equals("add".toString())){
                    JSONObject userAdd = user;
                    if( userAdd == null) {
                        LOGGER.info("add admin");
                        userAdd = new JSONObject();
                        final ResourceBundle init = ResourceBundle.getBundle("init");
                        userAdd.put(User.USER_EMAIL, userDelegateId + "@qq.com");
                        userAdd.put(User.USER_NAME, userName);
                        userAdd.put(User.USER_PASSWORD, MD5.hash(init.getString("admin.password")));
                        userAdd.put(UserExt.USER_DELEGATE_ID, userDelegateId);
                        userAdd.put(UserExt.USER_THIRD_PARTY_COMPANY_ID, userCompanyId);
                        userAdd.put(UserExt.USER_FROM, userFrom);
                        userAdd.put(User.USER_ROLE, Role.ADMIN_ROLE);
                        userAdd.put(UserExt.USER_STATUS, UserExt.USER_STATUS_C_VALID);
                        final String adminId = userMgmtService.addUser(userAdd);
                        userAdd.put(Keys.OBJECT_ID, adminId);
                    }
                } else {

                }
            }
        }

        context.renderTrueResult();

    }

}




