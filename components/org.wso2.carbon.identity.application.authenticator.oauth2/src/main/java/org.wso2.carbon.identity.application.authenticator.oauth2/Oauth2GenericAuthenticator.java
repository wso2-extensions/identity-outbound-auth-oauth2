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
package org.wso2.carbon.identity.application.authenticator.oauth2;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthAuthzResponse;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.apache.oltu.oauth2.common.utils.JSONUtils;
import org.json.JSONObject;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.ApplicationAuthenticatorException;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.core.util.IdentityIOStreamUtils;
import org.wso2.carbon.identity.core.util.IdentityUtil;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/* Oauth2GenericAuthenticator supports federating authentication with External Oauth IDP s from WSO2 IAM */
public class Oauth2GenericAuthenticator extends AbstractApplicationAuthenticator
        implements FederatedApplicationAuthenticator {

    private static final long serialVersionUID = 8654763286341993633L;
    private static final Log logger = LogFactory.getLog(Oauth2GenericAuthenticator.class);
    private String tokenEndpoint;
    private String oAuthEndpoint;
    private String userInfoEndpoint;
    private String stateToken;

    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {

        if (logger.isDebugEnabled()) {
            logger.debug("initiateAuthenticationRequest");
        }

        String stateToken = generateState();
        this.stateToken = stateToken;

        try {
            Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
            String clientId = authenticatorProperties.get(Oauth2GenericAuthenticatorConstants.CLIENT_ID);
            String callbackUrl = authenticatorProperties.get(Oauth2GenericAuthenticatorConstants.CALLBACK_URL);

            String authorizationEP = getAuthorizationServerEndpoint(authenticatorProperties);

            context.setContextIdentifier(stateToken);

            String state = stateToken + "," + Oauth2GenericAuthenticatorConstants.OAUTH2_LOGIN_TYPE;
            OAuthClientRequest authzRequest = OAuthClientRequest.authorizationLocation(authorizationEP)
                    .setClientId(clientId).setResponseType("code").setRedirectURI(callbackUrl)
                    .setState(state)
                    .buildQueryMessage();

            if (logger.isDebugEnabled()) {
                logger.debug("authzRequest");
                logger.debug(authzRequest.getLocationUri());
            }

            response.sendRedirect(authzRequest.getLocationUri());
        } catch (IOException e) {
            logger.error("Exception while sending to the login page.", e);
            throw new AuthenticationFailedException(e.getMessage(), e);
        } catch (OAuthSystemException e) {
            logger.error("Exception while building authorization code request.", e);
            throw new AuthenticationFailedException(e.getMessage(), e);
        }
    }

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {

        if (logger.isDebugEnabled()) {
            logger.debug("processAuthenticationResponse");
        }

        try {
            Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
            String clientId = authenticatorProperties.get(Oauth2GenericAuthenticatorConstants.CLIENT_ID);
            String clientSecret = authenticatorProperties.get(Oauth2GenericAuthenticatorConstants.CLIENT_SECRET);
            String code = getAuthorizationCode(request);

            String tokenEP = getTokenEndpoint(authenticatorProperties);
            String token = getToken(tokenEP, clientId, clientSecret, code);
            String userInfoEP = getUserInfoEndpoint(authenticatorProperties);
            String responseBody = getUserInfo(userInfoEP, token);
            if (logger.isDebugEnabled()) {
                logger.debug("Get user info response : " + responseBody);
            }

            buildClaims(context, responseBody);
        } catch (ApplicationAuthenticatorException e) {
            logger.error("Failed to process Connect response.", e);
            throw new AuthenticationFailedException(e.getMessage(), e);
        }

    }

    protected void buildClaims(AuthenticationContext context, String userInfoString)
            throws ApplicationAuthenticatorException, AuthenticationFailedException {

        if (userInfoString != null) {
            Map<String, Object> userInfoJson = JSONUtils.parseJSON(userInfoString);

            if (logger.isDebugEnabled()) {
                logger.debug("buildClaims");
            }

            Map<ClaimMapping, String> claims = new HashMap<>();

            for (Map.Entry<String, Object> entry : userInfoJson.entrySet()) {
                claims.put(

                        ClaimMapping.build(entry.getKey(), entry.getKey(), null, false), entry.getValue().toString());

                if (logger.isDebugEnabled()
                        && IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.USER_CLAIMS)) {
                    logger.debug("Adding claim mapping : " + entry.getKey() + " <> " + entry.getKey() + " : "
                            + entry.getValue());
                }

            }
            if (StringUtils
                    .isBlank(context.getExternalIdP().getIdentityProvider().getClaimConfig().getUserClaimURI())) {
                context.getExternalIdP().getIdentityProvider().getClaimConfig()
                        .setUserClaimURI(Oauth2GenericAuthenticatorConstants.EMAIL);
            }
            String subjectFromClaims = FrameworkUtils
                    .getFederatedSubjectFromClaims(context.getExternalIdP().getIdentityProvider(), claims);
            if (subjectFromClaims != null && !subjectFromClaims.isEmpty()) {
                AuthenticatedUser authenticatedUser = AuthenticatedUser
                        .createFederateAuthenticatedUserFromSubjectIdentifier(subjectFromClaims);
                context.setSubject(authenticatedUser);
            } else {
                setSubject(context, userInfoJson);
            }
            context.getSubject().setUserAttributes(claims);

        } else {
            if (logger.isDebugEnabled()) {
                logger.debug("Decoded json object is null");
            }
            throw new AuthenticationFailedException("Decoded json object is null");
        }

    }

    protected void setSubject(AuthenticationContext context, Map<String, Object> jsonObject)
            throws ApplicationAuthenticatorException {

        String authenticatedUserId = jsonObject.get(Oauth2GenericAuthenticatorConstants.DEFAULT_USER_IDENTIFIER)
                .toString();
        if (StringUtils.isEmpty(authenticatedUserId)) {
            throw new ApplicationAuthenticatorException("Authenticated user identifier is empty");
        }
        AuthenticatedUser authenticatedUser = AuthenticatedUser
                .createFederateAuthenticatedUserFromSubjectIdentifier(authenticatedUserId);
        context.setSubject(authenticatedUser);
    }

    protected String getToken(String tokenEndPoint, String clientId, String clientSecret, String code)
            throws ApplicationAuthenticatorException {

        OAuthClientRequest tokenRequest = null;
        String token;
        String tokenResponseStr;
        try {
            String state = this.stateToken;
            tokenRequest = buidTokenRequest(tokenEndPoint, clientId, clientSecret, state, code);
            tokenResponseStr = sendRequest(tokenRequest.getLocationUri());
            JSONObject tokenResponse = new JSONObject(tokenResponseStr);
            token = tokenResponse.getString("access_token");
            if (StringUtils.isEmpty(token) || StringUtils.isBlank(token))
                throw new ApplicationAuthenticatorException("Received access token is invalid.");

        } catch (
                MalformedURLException e) {
            if (logger.isDebugEnabled()) {
                logger.debug("URL : " + tokenRequest.getLocationUri());
            }
            throw new ApplicationAuthenticatorException("MalformedURLException while sending access token request.", e);
        } catch (
                IOException e) {
            throw new ApplicationAuthenticatorException("IOException while sending access token request.", e);
        }
        return token;
    }

    protected String getAuthorizationCode(HttpServletRequest request) throws ApplicationAuthenticatorException {

        OAuthAuthzResponse authzResponse;
        try {
            authzResponse = OAuthAuthzResponse.oauthCodeAuthzResponse(request);
            return authzResponse.getCode();
        } catch (OAuthProblemException e) {
            throw new ApplicationAuthenticatorException("Exception while reading authorization code.", e);
        }
    }

    protected String sendRequest(String url) throws IOException {

        BufferedReader bufferReader = null;
        StringBuilder stringBuilder = new StringBuilder();

        try {
            URLConnection urlConnection = new URL(url).openConnection();
            bufferReader = new BufferedReader(
                    new InputStreamReader(urlConnection.getInputStream(), StandardCharsets.UTF_8));

            String inputLine = bufferReader.readLine();
            while (inputLine != null) {
                stringBuilder.append(inputLine).append("\n");
                inputLine = bufferReader.readLine();
            }
        } finally {
            IdentityIOStreamUtils.closeReader(bufferReader);
        }

        return stringBuilder.toString();
    }

    protected OAuthClientRequest buidTokenRequest(String tokenEndPoint, String clientId, String clientSecret,
                                                  String state, String code) throws ApplicationAuthenticatorException {

        OAuthClientRequest tokenRequest;
        try {
            tokenRequest = OAuthClientRequest.tokenLocation(tokenEndPoint).setClientId(clientId)
                    .setClientSecret(clientSecret).setGrantType(GrantType.AUTHORIZATION_CODE).setCode(code)
                    .setParameter("state", state).buildQueryMessage();
        } catch (OAuthSystemException e) {
            throw new ApplicationAuthenticatorException("Exception while building access token request.", e);
        }
        return tokenRequest;
    }

    @Override
    public List<Property> getConfigurationProperties() {

        List<Property> configProperties = new ArrayList<>();

        Property clientId = new Property();
        clientId.setName(Oauth2GenericAuthenticatorConstants.CLIENT_ID);
        clientId.setDisplayName("Client Id");
        clientId.setRequired(true);
        clientId.setDescription("Enter client identifier value");
        configProperties.add(clientId);

        Property clientSecret = new Property();
        clientSecret.setName(Oauth2GenericAuthenticatorConstants.CLIENT_SECRET);
        clientSecret.setDisplayName("Client Secret");
        clientSecret.setRequired(true);
        clientSecret.setConfidential(true);
        clientSecret.setDescription("Enter client secret value");
        configProperties.add(clientSecret);

        Property callbackUrl = new Property();
        callbackUrl.setName(Oauth2GenericAuthenticatorConstants.CALLBACK_URL);
        callbackUrl.setDisplayName("Callback Url");
        callbackUrl.setRequired(true);
        callbackUrl.setDescription("Enter callback url");
        configProperties.add(callbackUrl);

        Property authorizationUrl = new Property();
        authorizationUrl.setName(Oauth2GenericAuthenticatorConstants.OAUTH_AUTHZ_URL);
        authorizationUrl.setDisplayName("Authorization Endpoint Url");
        authorizationUrl.setRequired(true);
        authorizationUrl.setDescription("Enter authorization endpoint url");
        configProperties.add(authorizationUrl);

        Property tokenUrl = new Property();
        tokenUrl.setName(Oauth2GenericAuthenticatorConstants.OAUTH_TOKEN_URL);
        tokenUrl.setDisplayName("Token Endpoint Url");
        tokenUrl.setRequired(true);
        tokenUrl.setDescription("Enter token endpoint url");
        configProperties.add(tokenUrl);

        Property userInfoUrl = new Property();
        userInfoUrl.setName(Oauth2GenericAuthenticatorConstants.OAUTH_USER_INFO_URL);
        userInfoUrl.setDisplayName("User Information Endpoint Url");
        userInfoUrl.setRequired(true);
        userInfoUrl.setDescription("Enter user information endpoint url");
        configProperties.add(userInfoUrl);

        Property scope = new Property();
        scope.setName(Oauth2GenericAuthenticatorConstants.SCOPE);
        scope.setDisplayName("Scope");
        scope.setRequired(false);
        scope.setDescription("Enter the scope");
        configProperties.add(scope);

        return configProperties;
    }

    protected String getUserInfo(String apiUrl, String token) {

        Map<String, String> requestHeaders = new HashMap<>();
        requestHeaders.put("Authorization", "Bearer " + token);

        HttpURLConnection con = connect(apiUrl);
        try {
            con.setRequestMethod("GET");
            for (Map.Entry<String, String> header : requestHeaders.entrySet())
                con.setRequestProperty(header.getKey(), header.getValue());

            int responseCode = con.getResponseCode();
            if (responseCode == HttpURLConnection.HTTP_OK) {
                return readBody(con.getInputStream());
            } else {
                return readBody(con.getErrorStream());
            }
        } catch (IOException e) {
            throw new RuntimeException("API Invoke failed", e);
        } finally {
            con.disconnect();
        }
    }

    protected HttpURLConnection connect(String apiUrl) {

        try {
            URL url = new URL(apiUrl);
            return (HttpURLConnection) url.openConnection();
        } catch (MalformedURLException e) {
            throw new RuntimeException("API URL is Invalid. : " + apiUrl, e);
        } catch (IOException e) {
            throw new RuntimeException("Connection failed. : " + apiUrl, e);
        }
    }

    protected String readBody(InputStream body) {

        InputStreamReader streamReader = new InputStreamReader(body);

        try (BufferedReader lineReader = new BufferedReader(streamReader)) {
            StringBuilder responseBody = new StringBuilder();

            String line;
            while ((line = lineReader.readLine()) != null) {
                responseBody.append(line);
            }

            return responseBody.toString();
        } catch (IOException e) {
            throw new RuntimeException("API Failed to read response.", e);
        }
    }

    protected boolean isOauth2CodeParamExists(HttpServletRequest request) {

        return request.getParameter(Oauth2GenericAuthenticatorConstants.OAUTH2_GRANT_TYPE_CODE) != null;
    }

    protected String getLoginType(HttpServletRequest request) {

        String state = request.getParameter(Oauth2GenericAuthenticatorConstants.OAUTH2_PARAM_STATE);
        if (StringUtils.isNotBlank(state) && state.split(",").length > 1) {
            return state.split(",")[1];
        } else {
            return null;
        }
    }

    protected boolean isOauthStateParamExists(HttpServletRequest request) {

        return request.getParameter(Oauth2GenericAuthenticatorConstants.OAUTH2_PARAM_STATE) != null
                && Oauth2GenericAuthenticatorConstants.OAUTH2_LOGIN_TYPE.equals(getLoginType(request));
    }

    @Override
    public boolean canHandle(HttpServletRequest request) {

        return isOauthStateParamExists(request) && isOauth2CodeParamExists(request);
    }

    @Override
    public String getContextIdentifier(HttpServletRequest request) {

        String state;
        try {
            state = OAuthAuthzResponse.oauthCodeAuthzResponse(request).getState();
            return state.split(",")[0];

        } catch (OAuthProblemException e1) {
            logger.error("No context");
            e1.printStackTrace();
            return null;
        }
    }

    protected String generateState() {

        SecureRandom random = new SecureRandom();
        return new BigInteger(130, random).toString(32);
    }

    @Override
    public String getFriendlyName() {

        return "OAUTH2";
    }

    @Override
    public String getName() {

        return Oauth2GenericAuthenticatorConstants.AUTHENTICATOR_NAME;
    }

    protected void initTokenEndpoint(Map<String, String> authenticatorProperties) {

        String tokenUrl = authenticatorProperties.get(Oauth2GenericAuthenticatorConstants.OAUTH_TOKEN_URL);
        if (StringUtils.isEmpty(tokenUrl))
            this.tokenEndpoint = getAuthenticatorConfig().getParameterMap()
                    .get(Oauth2GenericAuthenticatorConstants.OAUTH_TOKEN_URL);
        this.tokenEndpoint = tokenUrl;
    }

    protected void initOAuthEndpoint(Map<String, String> authenticatorProperties) {

        String oAuthUrl = authenticatorProperties.get(Oauth2GenericAuthenticatorConstants.OAUTH_AUTHZ_URL);
        if (StringUtils.isEmpty(oAuthUrl))
            this.oAuthEndpoint = getAuthenticatorConfig().getParameterMap()
                    .get(Oauth2GenericAuthenticatorConstants.OAUTH_AUTHZ_URL);
        this.oAuthEndpoint = oAuthUrl;
    }

    protected void initUserInfoEndPoint(Map<String, String> authenticatorProperties) {

        String userInfoUrl = authenticatorProperties.get(Oauth2GenericAuthenticatorConstants.OAUTH_USER_INFO_URL);
        if (StringUtils.isEmpty(userInfoUrl))
            this.userInfoEndpoint = getAuthenticatorConfig().getParameterMap()
                    .get(Oauth2GenericAuthenticatorConstants.OAUTH_USER_INFO_URL);
        this.userInfoEndpoint = userInfoUrl;
    }

    protected String getTokenEndpoint(Map<String, String> authenticatorProperties) {

        if (StringUtils.isBlank(this.tokenEndpoint)) {
            initTokenEndpoint(authenticatorProperties);
        }
        return this.tokenEndpoint;
    }

    protected String getAuthorizationServerEndpoint(Map<String, String> authenticatorProperties) {

        if (StringUtils.isBlank(this.oAuthEndpoint)) {
            initOAuthEndpoint(authenticatorProperties);
        }

        return this.oAuthEndpoint;
    }

    protected String getUserInfoEndpoint(Map<String, String> authenticatorProperties) {

        if (StringUtils.isBlank(this.userInfoEndpoint)) {
            initUserInfoEndPoint(authenticatorProperties);
        }
        return this.userInfoEndpoint;
    }

}
