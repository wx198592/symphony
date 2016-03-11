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
import org.b3log.latke.util.Requests;
import org.b3log.latke.util.Strings;
import org.b3log.symphony.model.Common;
import org.b3log.symphony.model.UserExt;
import org.b3log.symphony.model.Verifycode;
import org.b3log.symphony.model.Vote;
import org.b3log.symphony.service.UserMgmtService;
import org.b3log.symphony.service.UserQueryService;
import org.json.JSONObject;

import java.util.Date;

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
//        final String userIcon = requestJSONObject.optString(Common.THIRD_PARTY_USER_ICON);
        LOGGER.info(requestJSONObject.toString());

        String code = RandomStringUtils.randomAlphanumeric(15);

        JSONObject user = userQueryService.getUserByDelegateIdAndCompanyId(userDelegateId, userCompanyId);
        if( user == null) {
            user = new JSONObject();
            user.put(User.USER_NAME, userName);
            user.put(User.USER_EMAIL, userDelegateId + "@default.com");
            user.put(User.USER_PASSWORD, "");
            user.put(UserExt.USER_FROM, userFrom);
            user.put(UserExt.USER_DELEGATE_ID, userDelegateId);
            user.put(UserExt.USER_THIRD_PARTY_COMPANY_ID, userCompanyId);
            user.put(UserExt.USER_THIRD_PARTY_KEY, code);
            user.put(UserExt.USER_STATUS, UserExt.USER_STATUS_C_VALID);
//            user.put(UserExt.USER_AVATAR_URL, userIcon);


            try {
                final String newUserId = userMgmtService.addUser(user);
            } catch (final ServiceException e) {
                final String msg = langPropsService.get("registerFailLabel") + " - " + e.getMessage();
                LOGGER.log(Level.ERROR, msg + "[name={0}]", userName);

                context.renderMsg(msg);
            }
        } else {
            user.put(UserExt.USER_THIRD_PARTY_KEY, code);
            userMgmtService.updateThirdPartyKey(user);
        }

        context.renderTrueResult().renderJSONValue(Common.THIRD_PARTY_KEY, code);
    }

}



