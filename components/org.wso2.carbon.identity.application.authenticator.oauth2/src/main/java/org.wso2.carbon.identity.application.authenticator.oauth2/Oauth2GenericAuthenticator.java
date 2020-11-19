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

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthAuthzResponse;
import org.apache.oltu.oauth2.common.OAuth;
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
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.HttpMethod;
import javax.ws.rs.core.HttpHeaders;

import static javax.ws.rs.core.HttpHeaders.CONTENT_TYPE;
import static javax.ws.rs.core.MediaType.APPLICATION_FORM_URLENCODED;

/***
 * Oauth2GenericAuthenticator supports federating authentication with External Oauth IDP s from WSO2 IAM.
 */
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
                    .setClientId(clientId).setResponseType(Oauth2GenericAuthenticatorConstants.OAUTH2_GRANT_TYPE_CODE)
                    .setRedirectURI(callbackUrl)
                    .setState(state)
                    .setScope(authenticatorProperties.get(Oauth2GenericAuthenticatorConstants.SCOPE))
                    .buildQueryMessage();

            if (logger.isDebugEnabled()) {
                logger.debug("Authorization Request: " + authzRequest.getLocationUri());
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
        tokenEndpoint = null;
        oAuthEndpoint = null;
        userInfoEndpoint = null;

        try {
            Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
            String clientId = authenticatorProperties.get(Oauth2GenericAuthenticatorConstants.CLIENT_ID);
            String clientSecret = authenticatorProperties.get(Oauth2GenericAuthenticatorConstants.CLIENT_SECRET);
            String redirectUri = authenticatorProperties.get(Oauth2GenericAuthenticatorConstants.CALLBACK_URL);
            Boolean basicAuthEnabled = Boolean.parseBoolean(
                    authenticatorProperties.get(Oauth2GenericAuthenticatorConstants.IS_BASIC_AUTH_ENABLED));
            String authenticationMethod = authenticatorProperties.get(Oauth2GenericAuthenticatorConstants.CLAIM_RETRIEVING_METHOD);
            String code = getAuthorizationCode(request);
            String tokenEP = getTokenEndpoint(authenticatorProperties);
            String token = getToken(tokenEP, clientId, clientSecret, code, redirectUri, basicAuthEnabled);
            String userInfoEP = getUserInfoEndpoint(authenticatorProperties);
            String userInfo = getUserInfo(authenticationMethod, token, userInfoEP);

            if (logger.isDebugEnabled()) {
                logger.debug("Get user info response : " + userInfo);
            }

            buildClaims(context, userInfo);
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
                        ClaimMapping.build(entry.getKey(), entry.getKey(), null, false),
                        entry.getValue().toString());
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
            if (StringUtils.isBlank(subjectFromClaims)) {
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

        String authenticatedUserId = jsonObject.get(context.getExternalIdP().getIdentityProvider().getClaimConfig().getUserClaimURI())
                .toString();
        if (StringUtils.isEmpty(authenticatedUserId)) {
            throw new ApplicationAuthenticatorException("Authenticated user identifier is empty");
        }
        AuthenticatedUser authenticatedUser = AuthenticatedUser
                .createFederateAuthenticatedUserFromSubjectIdentifier(authenticatedUserId);
        context.setSubject(authenticatedUser);
    }

    protected String getToken(String tokenEndPoint, String clientId, String clientSecret, String code,
                              String redirectUri, Boolean basicAuthEnabled)
            throws ApplicationAuthenticatorException {

        OAuthClientRequest tokenRequest = null;
        String token;
        String tokenResponseStr;
        try {
            String state = this.stateToken;
            tokenRequest = buildTokenRequest(tokenEndPoint, clientId, clientSecret, state, code, redirectUri,
                    basicAuthEnabled);
            tokenResponseStr = sendRequest(tokenRequest.getLocationUri());
            JSONObject tokenResponse = new JSONObject(tokenResponseStr);
            token = tokenResponse.getString(Oauth2GenericAuthenticatorConstants.ACCESS_TOKEN);
            if (StringUtils.isBlank(token)) {
                throw new ApplicationAuthenticatorException("Received access token is invalid.");
            }
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
            HttpURLConnection urlConnection = (HttpURLConnection) new URL(url).openConnection();
            urlConnection.setDoOutput(true);
            urlConnection.setRequestProperty(CONTENT_TYPE, APPLICATION_FORM_URLENCODED);
            urlConnection.setRequestMethod(HttpMethod.POST);

            bufferReader = new BufferedReader(
                    new InputStreamReader(urlConnection.getInputStream(), StandardCharsets.UTF_8));

            String inputLine = bufferReader.readLine();
            while (inputLine != null) {
                stringBuilder.append(inputLine).append(Oauth2GenericAuthenticatorConstants.NEW_LINE);
                inputLine = bufferReader.readLine();
            }
        } finally {
            IdentityIOStreamUtils.closeReader(bufferReader);
        }
        return stringBuilder.toString();
    }

    protected OAuthClientRequest buildTokenRequest(String tokenEndPoint, String clientId, String clientSecret,
                                                   String state, String code, String redirectUri, Boolean basicAuthEnabled) throws ApplicationAuthenticatorException {

        OAuthClientRequest tokenRequest;
        try {
            if (!basicAuthEnabled) {
                tokenRequest = OAuthClientRequest.tokenLocation(tokenEndPoint).setClientId(clientId)
                        .setClientSecret(clientSecret).setGrantType(GrantType.AUTHORIZATION_CODE).setCode(code)
                        .setRedirectURI(redirectUri)
                        .setParameter(Oauth2GenericAuthenticatorConstants.OAUTH2_PARAM_STATE, state)
                        .buildQueryMessage();
            } else {
                tokenRequest = OAuthClientRequest.tokenLocation(tokenEndPoint)
                        .setGrantType(GrantType.AUTHORIZATION_CODE)
                        .setRedirectURI(redirectUri)
                        .setCode(code)
                        .buildQueryMessage();
                String base64EncodedCredential =
                        new String(Base64.encodeBase64((clientId + Oauth2GenericAuthenticatorConstants.COLON +
                                clientSecret).getBytes()));
                tokenRequest.addHeader(OAuth.HeaderType.AUTHORIZATION,
                        Oauth2GenericAuthenticatorConstants.AUTH_TYPE + base64EncodedCredential);
            }
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
        clientId.setDisplayName(Oauth2GenericAuthenticatorConstants.CLIENT_ID_DP);
        clientId.setRequired(true);
        clientId.setDescription(Oauth2GenericAuthenticatorConstants.CLIENT_ID_DESC);
        clientId.setDisplayOrder(1);
        configProperties.add(clientId);

        Property clientSecret = new Property();
        clientSecret.setName(Oauth2GenericAuthenticatorConstants.CLIENT_SECRET);
        clientSecret.setDisplayName(Oauth2GenericAuthenticatorConstants.CLIENT_SECRET_DP);
        clientSecret.setRequired(true);
        clientSecret.setConfidential(true);
        clientSecret.setDescription(Oauth2GenericAuthenticatorConstants.CLIENT_SECRET_DESC);
        clientSecret.setDisplayOrder(2);
        configProperties.add(clientSecret);

        Property callbackUrl = new Property();
        callbackUrl.setName(Oauth2GenericAuthenticatorConstants.CALLBACK_URL);
        callbackUrl.setDisplayName(Oauth2GenericAuthenticatorConstants.CALLBACK_URL_DP);
        callbackUrl.setRequired(true);
        callbackUrl.setDescription(Oauth2GenericAuthenticatorConstants.CALLBACK_URL_DESC);
        callbackUrl.setDisplayOrder(3);
        configProperties.add(callbackUrl);

        Property authorizationUrl = new Property();
        authorizationUrl.setName(Oauth2GenericAuthenticatorConstants.OAUTH_AUTHZ_URL);
        authorizationUrl.setDisplayName(Oauth2GenericAuthenticatorConstants.OAUTH_AUTHZ_URL_DP);
        authorizationUrl.setRequired(true);
        authorizationUrl.setDescription(Oauth2GenericAuthenticatorConstants.OAUTH_AUTHZ_URL_DESC);
        authorizationUrl.setDisplayOrder(4);
        configProperties.add(authorizationUrl);

        Property tokenUrl = new Property();
        tokenUrl.setName(Oauth2GenericAuthenticatorConstants.OAUTH_TOKEN_URL);
        tokenUrl.setDisplayName(Oauth2GenericAuthenticatorConstants.OAUTH_TOKEN_URL_DP);
        tokenUrl.setRequired(true);
        tokenUrl.setDescription(Oauth2GenericAuthenticatorConstants.OAUTH_TOKEN_URL_DESC);
        tokenUrl.setDisplayOrder(5);
        configProperties.add(tokenUrl);

        Property userInfoUrl = new Property();
        userInfoUrl.setName(Oauth2GenericAuthenticatorConstants.OAUTH_USER_INFO_URL);
        userInfoUrl.setDisplayName(Oauth2GenericAuthenticatorConstants.OAUTH_USER_INFO_URL_DP);
        userInfoUrl.setRequired(true);
        userInfoUrl.setDescription(Oauth2GenericAuthenticatorConstants.OAUTH_USER_INFO_URL_DESC);
        userInfoUrl.setDisplayOrder(6);
        configProperties.add(userInfoUrl);

        Property scope = new Property();
        scope.setName(Oauth2GenericAuthenticatorConstants.SCOPE);
        scope.setDisplayName(Oauth2GenericAuthenticatorConstants.SCOPE_DP);
        scope.setRequired(false);
        scope.setDescription(Oauth2GenericAuthenticatorConstants.SCOPE_DESC);
        scope.setDisplayOrder(7);
        configProperties.add(scope);

        Property enableBasicAuth = new Property();
        enableBasicAuth.setName(Oauth2GenericAuthenticatorConstants.IS_BASIC_AUTH_ENABLED);
        enableBasicAuth.setDisplayName(Oauth2GenericAuthenticatorConstants.IS_BASIC_AUTH_ENABLED_DP);
        enableBasicAuth.setRequired(false);
        enableBasicAuth.setDescription(Oauth2GenericAuthenticatorConstants.IS_BASIC_AUTH_ENABLED_DESC);
        enableBasicAuth.setType(Oauth2GenericAuthenticatorConstants.VAR_TYPE_BOOLEAN);
        enableBasicAuth.setDisplayOrder(8);
        configProperties.add(enableBasicAuth);

        Property claimRetrievingMethod = new Property();
        claimRetrievingMethod.setName(Oauth2GenericAuthenticatorConstants.CLAIM_RETRIEVING_METHOD);
        claimRetrievingMethod.setDisplayName(Oauth2GenericAuthenticatorConstants.CLAIM_RETRIEVING_METHOD_DP);
        claimRetrievingMethod.setRequired(false);
        claimRetrievingMethod.setDescription(Oauth2GenericAuthenticatorConstants.CLAIM_RETRIEVING_METHOD_DESC);
        claimRetrievingMethod.setType("string");
        claimRetrievingMethod.setDisplayOrder(9);
        claimRetrievingMethod.setDefaultValue(Oauth2GenericAuthenticatorConstants.CLAIM_RETRIEVING_METHOD_DEFAULT);
        configProperties.add(claimRetrievingMethod);

        return configProperties;
    }

    protected String getUserInfoFromURL(String apiUrl, String token) {

        Map<String, String> requestHeaders = new HashMap<>();
        requestHeaders.put(HttpHeaders.AUTHORIZATION,
                Oauth2GenericAuthenticatorConstants.TOKEN_TYPE + token);

        HttpURLConnection con = connect(apiUrl);
        try {
            con.setRequestMethod(HttpMethod.GET);
            for (Map.Entry<String, String> header : requestHeaders.entrySet()) {
                con.setRequestProperty(header.getKey(), header.getValue());
            }
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

    protected String getUserInfo(String authenticationMethod, String token, String userInfoEP) {

        String userInfo = null;

        if (authenticationMethod.replaceAll("\\s", "").toLowerCase().
                contains(Oauth2GenericAuthenticatorConstants.CLAIM_RETRIEVING_METHOD_DEFAULT)) {
            String responseBody = getUserInfoFromURL(userInfoEP, token);
            userInfo = responseBody;
        } else {
            String tokenBody = decodeAccessToken(token);
            if (!StringUtils.isBlank(tokenBody)) {
                userInfo = tokenBody;
            }
        }

        return userInfo;
    }

    protected String decodeAccessToken(String token) {

        String[] split_string = token.split("\\.");
        String payload = null;
        if (split_string.length > 1) {
            String base64EncodedBody = split_string[1];

            String body = new String(Base64.decodeBase64(base64EncodedBody));
            payload = body;
        }
        
        return payload;
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
        } catch (IndexOutOfBoundsException e2) {
            logger.error("No state returned");
            e2.printStackTrace();
            return null;
        }
    }

    protected String generateState() {

        SecureRandom random = new SecureRandom();
        return new BigInteger(130, random).toString(32);
    }

    @Override
    public String getFriendlyName() {

        return Oauth2GenericAuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    @Override
    public String getName() {

        return Oauth2GenericAuthenticatorConstants.AUTHENTICATOR_NAME;
    }

    protected void initTokenEndpoint(Map<String, String> authenticatorProperties) {

        String tokenUrl = authenticatorProperties.get(Oauth2GenericAuthenticatorConstants.OAUTH_TOKEN_URL);
        if (StringUtils.isEmpty(tokenUrl)) {
            this.tokenEndpoint = getAuthenticatorConfig().getParameterMap()
                    .get(Oauth2GenericAuthenticatorConstants.OAUTH_TOKEN_URL);
        } else {
            this.tokenEndpoint = tokenUrl;
        }
    }

    protected void initOAuthEndpoint(Map<String, String> authenticatorProperties) {

        String oAuthUrl = authenticatorProperties.get(Oauth2GenericAuthenticatorConstants.OAUTH_AUTHZ_URL);
        if (StringUtils.isEmpty(oAuthUrl)) {
            this.oAuthEndpoint = getAuthenticatorConfig().getParameterMap()
                    .get(Oauth2GenericAuthenticatorConstants.OAUTH_AUTHZ_URL);
        } else {
            this.oAuthEndpoint = oAuthUrl;
        }
    }

    protected void initUserInfoEndPoint(Map<String, String> authenticatorProperties) {

        String userInfoUrl = authenticatorProperties.get(Oauth2GenericAuthenticatorConstants.OAUTH_USER_INFO_URL);
        if (StringUtils.isEmpty(userInfoUrl)) {
            this.userInfoEndpoint = getAuthenticatorConfig().getParameterMap()
                    .get(Oauth2GenericAuthenticatorConstants.OAUTH_USER_INFO_URL);
        } else {
            this.userInfoEndpoint = userInfoUrl;
        }

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

