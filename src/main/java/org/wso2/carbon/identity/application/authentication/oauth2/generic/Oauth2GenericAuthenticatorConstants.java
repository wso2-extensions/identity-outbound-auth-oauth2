/*******************************************************************************
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 ******************************************************************************/
package org.wso2.carbon.identity.application.authentication.oauth2.generic;

public class Oauth2GenericAuthenticatorConstants {

    public static final String CLIENT_ID = "ClientId";
    public static final String CLIENT_SECRET = "ClientSecret";
    public static final String CALLBACK_URL = "CallbackUrl";

    public static final String OAUTH2_GRANT_TYPE_CODE = "code";
    public static final String EMAIL = "email";
    public static final String DEFAULT_USER_IDENTIFIER = "id";
    public static final String OAUTH2_PARAM_STATE = "state";
    public static final String OAUTH2_LOGIN_TYPE = "oauth2";
    public static final String AUTHENTICATOR_NAME = "OAUTH2";

    public static final String OAUTH_AUTHZ_URL = "AuthnEndpoint";
    public static final String OAUTH_TOKEN_URL = "AuthTokenEndpoint";
    public static final String OAUTH_USER_INFO_URL = "UserInfoEndpoint";
}
