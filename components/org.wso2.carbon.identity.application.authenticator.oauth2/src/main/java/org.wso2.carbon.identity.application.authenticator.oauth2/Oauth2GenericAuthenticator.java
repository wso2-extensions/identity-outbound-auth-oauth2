/*
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
 */
package org.wso2.carbon.identity.application.authenticator.oauth2;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.client.OAuthClient;
import org.apache.oltu.oauth2.client.URLConnectionClient;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthAuthzResponse;
import org.apache.oltu.oauth2.client.response.OAuthClientResponse;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.utils.JSONUtils;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.ApplicationAuthenticatorException;
import org.wso2.carbon.identity.application.authentication.framework.exception.MisconfigurationException;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.ClaimConfig;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.core.util.IdentityUtil;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static java.net.HttpURLConnection.HTTP_OK;
import static javax.ws.rs.HttpMethod.GET;
import static org.apache.oltu.oauth2.common.OAuth.HeaderType.AUTHORIZATION;
import static org.apache.oltu.oauth2.common.message.types.GrantType.AUTHORIZATION_CODE;
import static org.wso2.carbon.identity.application.authenticator.oauth2.Oauth2GenericAuthenticatorConstants.ACCESS_TOKEN;
import static org.wso2.carbon.identity.application.authenticator.oauth2.Oauth2GenericAuthenticatorConstants.AUTH_TYPE;
import static org.wso2.carbon.identity.application.authenticator.oauth2.Oauth2GenericAuthenticatorConstants.CALLBACK_URL;
import static org.wso2.carbon.identity.application.authenticator.oauth2.Oauth2GenericAuthenticatorConstants.CALLBACK_URL_DEFAULT;
import static org.wso2.carbon.identity.application.authenticator.oauth2.Oauth2GenericAuthenticatorConstants.CALLBACK_URL_DESC;
import static org.wso2.carbon.identity.application.authenticator.oauth2.Oauth2GenericAuthenticatorConstants.CALLBACK_URL_DP;
import static org.wso2.carbon.identity.application.authenticator.oauth2.Oauth2GenericAuthenticatorConstants.DEFAULT_PROTOCOL_IDENTIFIER;
import static org.wso2.carbon.identity.application.authenticator.oauth2.Oauth2GenericAuthenticatorConstants.SELF_CONTAINED_TOKEN_ENABLED;
import static org.wso2.carbon.identity.application.authenticator.oauth2.Oauth2GenericAuthenticatorConstants.SELF_CONTAINED_TOKEN_ENABLED_DEFAULT;
import static org.wso2.carbon.identity.application.authenticator.oauth2.Oauth2GenericAuthenticatorConstants.SELF_CONTAINED_TOKEN_ENABLED_DESC;
import static org.wso2.carbon.identity.application.authenticator.oauth2.Oauth2GenericAuthenticatorConstants.SELF_CONTAINED_TOKEN_ENABLED_DP;
import static org.wso2.carbon.identity.application.authenticator.oauth2.Oauth2GenericAuthenticatorConstants.CLIENT_ID;
import static org.wso2.carbon.identity.application.authenticator.oauth2.Oauth2GenericAuthenticatorConstants.CLIENT_ID_DESC;
import static org.wso2.carbon.identity.application.authenticator.oauth2.Oauth2GenericAuthenticatorConstants.CLIENT_ID_DP;
import static org.wso2.carbon.identity.application.authenticator.oauth2.Oauth2GenericAuthenticatorConstants.CLIENT_SECRET;
import static org.wso2.carbon.identity.application.authenticator.oauth2.Oauth2GenericAuthenticatorConstants.CLIENT_SECRET_DESC;
import static org.wso2.carbon.identity.application.authenticator.oauth2.Oauth2GenericAuthenticatorConstants.CLIENT_SECRET_DP;
import static org.wso2.carbon.identity.application.authenticator.oauth2.Oauth2GenericAuthenticatorConstants.EMAIL;
import static org.wso2.carbon.identity.application.authenticator.oauth2.Oauth2GenericAuthenticatorConstants.IS_BASIC_AUTH_ENABLED;
import static org.wso2.carbon.identity.application.authenticator.oauth2.Oauth2GenericAuthenticatorConstants.IS_BASIC_AUTH_ENABLED_DEFAULT;
import static org.wso2.carbon.identity.application.authenticator.oauth2.Oauth2GenericAuthenticatorConstants.IS_BASIC_AUTH_ENABLED_DESC;
import static org.wso2.carbon.identity.application.authenticator.oauth2.Oauth2GenericAuthenticatorConstants.IS_BASIC_AUTH_ENABLED_DP;
import static org.wso2.carbon.identity.application.authenticator.oauth2.Oauth2GenericAuthenticatorConstants.OAUTH2_AUTHZ_URL;
import static org.wso2.carbon.identity.application.authenticator.oauth2.Oauth2GenericAuthenticatorConstants.OAUTH2_AUTHZ_URL_DESC;
import static org.wso2.carbon.identity.application.authenticator.oauth2.Oauth2GenericAuthenticatorConstants.OAUTH2_AUTHZ_URL_DP;
import static org.wso2.carbon.identity.application.authenticator.oauth2.Oauth2GenericAuthenticatorConstants.OAUTH2_GRANT_TYPE_CODE;
import static org.wso2.carbon.identity.application.authenticator.oauth2.Oauth2GenericAuthenticatorConstants.OAUTH2_LOGIN_TYPE;
import static org.wso2.carbon.identity.application.authenticator.oauth2.Oauth2GenericAuthenticatorConstants.OAUTH2_TOKEN_URL;
import static org.wso2.carbon.identity.application.authenticator.oauth2.Oauth2GenericAuthenticatorConstants.OAUTH2_TOKEN_URL_DESC;
import static org.wso2.carbon.identity.application.authenticator.oauth2.Oauth2GenericAuthenticatorConstants.OAUTH2_TOKEN_URL_DP;
import static org.wso2.carbon.identity.application.authenticator.oauth2.Oauth2GenericAuthenticatorConstants.OAUTH2_USER_INFO_URL;
import static org.wso2.carbon.identity.application.authenticator.oauth2.Oauth2GenericAuthenticatorConstants.OAUTH2_USER_INFO_URL_DESC;
import static org.wso2.carbon.identity.application.authenticator.oauth2.Oauth2GenericAuthenticatorConstants.OAUTH2_USER_INFO_URL_DP;
import static org.wso2.carbon.identity.application.authenticator.oauth2.Oauth2GenericAuthenticatorConstants.SCOPE;
import static org.wso2.carbon.identity.application.authenticator.oauth2.Oauth2GenericAuthenticatorConstants.SCOPE_DESC;
import static org.wso2.carbon.identity.application.authenticator.oauth2.Oauth2GenericAuthenticatorConstants.SCOPE_DP;
import static org.wso2.carbon.identity.application.authenticator.oauth2.Oauth2GenericAuthenticatorConstants.TOKEN_TYPE;
import static org.wso2.carbon.identity.application.authenticator.oauth2.Oauth2GenericAuthenticatorConstants.VAR_TYPE_BOOLEAN;
import static org.wso2.carbon.identity.base.IdentityConstants.IdentityTokens.USER_CLAIMS;

/**
 * Oauth2GenericAuthenticator supports federated authentication with External Oauth2 IDP.
 */
public class Oauth2GenericAuthenticator extends AbstractApplicationAuthenticator
        implements FederatedApplicationAuthenticator {

    private static final long serialVersionUID = 8654763286341993633L;
    private static final Log logger = LogFactory.getLog(Oauth2GenericAuthenticator.class);

    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {

        if (logger.isDebugEnabled()) {
            logger.debug("Initiating authentication request");
        }
        String stateToken = generateState();
        try {
            Map<String, String> authenticatorProperties = getAuthenticatorProperties(context);
            String clientId = getClientId(authenticatorProperties);
            String callbackUrl = getCallbackURL(authenticatorProperties, request.getServerName(),
                    request.getServerPort());
            String authorizationEP = getAuthorizationServerEndpoint(authenticatorProperties);
            String scope = authenticatorProperties.get(SCOPE);
            String state = stateToken + "," + OAUTH2_LOGIN_TYPE;

            context.setContextIdentifier(stateToken);

            OAuthClientRequest authzRequest = OAuthClientRequest.authorizationLocation(authorizationEP)
                    .setClientId(clientId)
                    .setResponseType(OAUTH2_GRANT_TYPE_CODE)
                    .setRedirectURI(callbackUrl)
                    .setState(state)
                    .setScope(scope)
                    .buildQueryMessage();
            if (logger.isDebugEnabled()) {
                logger.debug("Authorization Request: " + authzRequest.getLocationUri());
            }
            response.sendRedirect(authzRequest.getLocationUri());

        } catch (IOException e) {
            String message = "Exception while redirecting to the login page.";
            logger.error(message, e);
            throw new AuthenticationFailedException(message, e);
        } catch (OAuthSystemException e) {
            String message = "Exception while building authorization code request.";
            logger.error(message, e);
            throw new AuthenticationFailedException(e.getMessage(), e);
        } catch (MisconfigurationException e) {
            logger.error(e.getMessage(), e);
            throw new AuthenticationFailedException(e.getMessage(), e);
        }
    }

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {

        if (logger.isDebugEnabled()) {
            logger.debug("Processing authentication response");
        }
        try {
            Map<String, String> authenticatorProperties = getAuthenticatorProperties(context);
            String clientId = getClientId(authenticatorProperties);
            String clientSecret = getClientSecret(authenticatorProperties);
            String redirectUri = getCallbackURL(authenticatorProperties, request.getServerName(),
                    request.getServerPort());
            Boolean basicAuthEnabled = Boolean.parseBoolean(
                    StringUtils.lowerCase(authenticatorProperties.get(IS_BASIC_AUTH_ENABLED)));
            Boolean selfContainedTokenEnabled = Boolean.parseBoolean(
                    StringUtils.lowerCase(authenticatorProperties.get(SELF_CONTAINED_TOKEN_ENABLED)));
            String code = getAuthorizationCode(request);
            String tokenEP = getTokenEndpoint(authenticatorProperties);
            String token = getToken(tokenEP, clientId, clientSecret, code, redirectUri, basicAuthEnabled);
            String userInfo = getUserInfo(selfContainedTokenEnabled, token, authenticatorProperties);
            if (logger.isDebugEnabled()) {
                logger.debug("Get user info: " + userInfo);
            }
            buildClaims(context, userInfo);

        } catch (ApplicationAuthenticatorException e) {
            throw new AuthenticationFailedException("Failed to process authentication response.", e);
        } catch (MisconfigurationException e) {
            logger.error(e.getMessage(), e);
            throw new AuthenticationFailedException(e.getMessage(), e);
        }
    }

    protected void buildClaims(AuthenticationContext context, String userInfoString)
            throws ApplicationAuthenticatorException {

        if (userInfoString != null) {
            Map<String, Object> userInfoJson = JSONUtils.parseJSON(userInfoString);
            if (logger.isDebugEnabled()) {
                logger.debug("Building user claims");
            }
            Map<ClaimMapping, String> claims = new HashMap<>();
            for (Map.Entry<String, Object> entry : userInfoJson.entrySet()) {
                claims.put(
                        ClaimMapping.build(entry.getKey(), entry.getKey(), null, false),
                        entry.getValue().toString());
                if (logger.isDebugEnabled() && IdentityUtil.isTokenLoggable(USER_CLAIMS)) {
                    logger.debug("Adding claim mapping : " + entry.getKey() + " <> " + entry.getKey() + " : "
                            + entry.getValue());
                }
            }
            ClaimConfig claimConfig = context.getExternalIdP().getIdentityProvider().getClaimConfig();
            if (StringUtils.isBlank(claimConfig.getUserClaimURI())) {
                claimConfig.setUserClaimURI(EMAIL);
            }
            String subjectFromClaims = FrameworkUtils
                    .getFederatedSubjectFromClaims(context.getExternalIdP().getIdentityProvider(), claims);
            if (!StringUtils.isBlank(subjectFromClaims)) {
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
            throw new ApplicationAuthenticatorException("Decoded json object is null");
        }
    }

    protected void setSubject(AuthenticationContext context, Map<String, Object> jsonObject)
            throws ApplicationAuthenticatorException {

        String authenticatedUserId = jsonObject.get(context.getExternalIdP().getIdentityProvider().
                getClaimConfig().getUserClaimURI())
                .toString();
        if (StringUtils.isBlank(authenticatedUserId)) {
            throw new ApplicationAuthenticatorException("Authenticated user identifier is empty");
        }
        AuthenticatedUser authenticatedUser = AuthenticatedUser
                .createFederateAuthenticatedUserFromSubjectIdentifier(authenticatedUserId);
        context.setSubject(authenticatedUser);
    }

    protected String getToken(String tokenEndPoint, String clientId, String clientSecret, String code,
                              String redirectUri, Boolean basicAuthEnabled)
            throws ApplicationAuthenticatorException {

        OAuthClientRequest tokenRequest = buildTokenRequest(tokenEndPoint, clientId, clientSecret, code, redirectUri,
                basicAuthEnabled);
        OAuthClient oAuthClient = new OAuthClient(new URLConnectionClient());
        OAuthClientResponse tokenResponse = getOauthResponse(oAuthClient, tokenRequest);
        String token = tokenResponse.getParam(ACCESS_TOKEN);
        if (StringUtils.isBlank(token)) {
            String errorMessage = "Access token is empty or null";
            if (logger.isDebugEnabled()) {
                logger.debug(errorMessage);
            }
            throw new ApplicationAuthenticatorException(errorMessage);
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

    private OAuthClientResponse getOauthResponse(OAuthClient oAuthClient, OAuthClientRequest accessRequest)
            throws ApplicationAuthenticatorException {

        OAuthClientResponse oAuthResponse;
        try {
            oAuthResponse = oAuthClient.accessToken(accessRequest);
            return oAuthResponse;
        } catch (OAuthSystemException | OAuthProblemException e) {
            if (logger.isDebugEnabled()) {
                logger.debug(e.getMessage());
            }
            throw new ApplicationAuthenticatorException(e.getMessage());
        }
    }

    protected OAuthClientRequest buildTokenRequest(String tokenEndPoint, String clientId, String clientSecret,
                                                   String code, String redirectUri, Boolean basicAuthEnabled)
            throws ApplicationAuthenticatorException {

        OAuthClientRequest tokenRequest;
        try {
            if (!basicAuthEnabled) {
                tokenRequest = OAuthClientRequest.tokenLocation(tokenEndPoint)
                        .setClientId(clientId)
                        .setClientSecret(clientSecret)
                        .setGrantType(AUTHORIZATION_CODE)
                        .setCode(code)
                        .setRedirectURI(redirectUri)
                        .buildBodyMessage();
            } else {
                tokenRequest = OAuthClientRequest.tokenLocation(tokenEndPoint)
                        .setGrantType(AUTHORIZATION_CODE)
                        .setRedirectURI(redirectUri)
                        .setCode(code)
                        .buildBodyMessage();
                String base64EncodedCredential =
                        new String(Base64.encodeBase64((clientId + ":" + clientSecret).getBytes()));
                tokenRequest.addHeader(AUTHORIZATION, AUTH_TYPE + base64EncodedCredential);
            }
            return tokenRequest;
        } catch (OAuthSystemException e) {
            throw new ApplicationAuthenticatorException("Exception while building access token request.", e);
        }
    }

    @Override
    public List<Property> getConfigurationProperties() {

        List<Property> configProperties = new ArrayList<>();

        Property clientId = new Property();
        clientId.setName(CLIENT_ID);
        clientId.setDisplayName(CLIENT_ID_DP);
        clientId.setRequired(true);
        clientId.setDescription(CLIENT_ID_DESC);
        clientId.setDisplayOrder(1);
        configProperties.add(clientId);

        Property clientSecret = new Property();
        clientSecret.setName(CLIENT_SECRET);
        clientSecret.setDisplayName(CLIENT_SECRET_DP);
        clientSecret.setRequired(true);
        clientSecret.setConfidential(true);
        clientSecret.setDescription(CLIENT_SECRET_DESC);
        clientSecret.setDisplayOrder(2);
        configProperties.add(clientSecret);

        Property callbackUrl = new Property();
        callbackUrl.setName(CALLBACK_URL);
        callbackUrl.setDisplayName(CALLBACK_URL_DP);
        callbackUrl.setRequired(true);
        callbackUrl.setDescription(CALLBACK_URL_DESC);
        callbackUrl.setDisplayOrder(3);
        configProperties.add(callbackUrl);

        Property authorizationUrl = new Property();
        authorizationUrl.setName(OAUTH2_AUTHZ_URL);
        authorizationUrl.setDisplayName(OAUTH2_AUTHZ_URL_DP);
        authorizationUrl.setRequired(true);
        authorizationUrl.setDescription(OAUTH2_AUTHZ_URL_DESC);
        authorizationUrl.setDisplayOrder(4);
        configProperties.add(authorizationUrl);

        Property tokenUrl = new Property();
        tokenUrl.setName(OAUTH2_TOKEN_URL);
        tokenUrl.setDisplayName(OAUTH2_TOKEN_URL_DP);
        tokenUrl.setRequired(true);
        tokenUrl.setDescription(OAUTH2_TOKEN_URL_DESC);
        tokenUrl.setDisplayOrder(5);
        configProperties.add(tokenUrl);

        Property userInfoUrl = new Property();
        userInfoUrl.setName(OAUTH2_USER_INFO_URL);
        userInfoUrl.setDisplayName(OAUTH2_USER_INFO_URL_DP);
        userInfoUrl.setRequired(true);
        userInfoUrl.setDescription(OAUTH2_USER_INFO_URL_DESC);
        userInfoUrl.setDisplayOrder(6);
        configProperties.add(userInfoUrl);

        Property scope = new Property();
        scope.setName(SCOPE);
        scope.setDisplayName(SCOPE_DP);
        scope.setRequired(false);
        scope.setDescription(SCOPE_DESC);
        scope.setDisplayOrder(7);
        configProperties.add(scope);

        Property enableBasicAuth = new Property();
        enableBasicAuth.setName(IS_BASIC_AUTH_ENABLED);
        enableBasicAuth.setDisplayName(IS_BASIC_AUTH_ENABLED_DP);
        enableBasicAuth.setRequired(false);
        enableBasicAuth.setDescription(IS_BASIC_AUTH_ENABLED_DESC);
        enableBasicAuth.setType(VAR_TYPE_BOOLEAN);
        enableBasicAuth.setDisplayOrder(8);
        enableBasicAuth.setDefaultValue(IS_BASIC_AUTH_ENABLED_DEFAULT);
        configProperties.add(enableBasicAuth);

        Property enableSelfContainedToken = new Property();
        enableSelfContainedToken.setName(SELF_CONTAINED_TOKEN_ENABLED);
        enableSelfContainedToken.setDisplayName(SELF_CONTAINED_TOKEN_ENABLED_DP);
        enableSelfContainedToken.setRequired(false);
        enableSelfContainedToken.setDescription(SELF_CONTAINED_TOKEN_ENABLED_DESC);
        enableSelfContainedToken.setType(VAR_TYPE_BOOLEAN);
        enableSelfContainedToken.setDisplayOrder(9);
        enableSelfContainedToken.setDefaultValue(SELF_CONTAINED_TOKEN_ENABLED_DEFAULT);
        configProperties.add(enableSelfContainedToken);

        return configProperties;
    }

    protected String getUserInfoFromURL(String apiUrl, String token) throws ApplicationAuthenticatorException {

        Map<String, String> requestHeaders = new HashMap<>();
        requestHeaders.put(AUTHORIZATION, TOKEN_TYPE + token);
        HttpURLConnection con = connect(apiUrl);
        try {
            con.setRequestMethod(GET);
            for (Map.Entry<String, String> header : requestHeaders.entrySet()) {
                con.setRequestProperty(header.getKey(), header.getValue());
            }
            int responseCode = con.getResponseCode();
            if (responseCode == HTTP_OK) {
                String responseBody = readBody(con.getInputStream());
                if (StringUtils.isBlank(responseBody)) {
                    String errorMessage = "Empty JSON response from user info endpoint. Unable to fetch user claims.";
                    if (logger.isDebugEnabled()) {
                        logger.debug(errorMessage);
                    }
                    throw new ApplicationAuthenticatorException(errorMessage);
                }
                return responseBody;
            } else {
                String errorMessage = "Error while retrieving user info from URL: " + apiUrl + " " + responseCode;
                if (logger.isDebugEnabled()) {
                    logger.debug(errorMessage);
                }
                throw new ApplicationAuthenticatorException(errorMessage);
            }
        } catch (IOException e) {
            throw new ApplicationAuthenticatorException(e.getMessage(), e);
        } finally {
            con.disconnect();
        }
    }

    protected String getUserInfo(Boolean selfContainedTokenEnabled, String token,
                                 Map<String, String> authenticatorProperties)
            throws MisconfigurationException, ApplicationAuthenticatorException {

        if (selfContainedTokenEnabled) {
            return decodeAccessToken(token);
        } else {
            String userInfoEP = getUserInfoEndpoint(authenticatorProperties);
            return getUserInfoFromURL(userInfoEP, token);
        }
    }

    protected String decodeAccessToken(String token) throws ApplicationAuthenticatorException {

        String[] split_string = token.split("\\.");
        if (split_string.length > 1) {
            String base64EncodedBody = split_string[1];
            String payload = new String(Base64.decodeBase64(base64EncodedBody));
            if (StringUtils.isBlank(payload)) {
                throw new ApplicationAuthenticatorException("Exception while decoding access token. " +
                        "Decoded token is null.");
            }
            return payload;
        } else {
            throw new ApplicationAuthenticatorException("Exception while decoding access token. " +
                    "Token does not contain a body.");
        }
    }

    protected HttpURLConnection connect(String apiUrl) {

        try {
            URL url = new URL(apiUrl);
            return (HttpURLConnection) url.openConnection();
        } catch (MalformedURLException e) {
            throw new RuntimeException("Invalid URL. : " + apiUrl, e);
        } catch (IOException e) {
            throw new RuntimeException("Connection failed. : " + apiUrl, e);
        }
    }

    protected String readBody(InputStream body) throws ApplicationAuthenticatorException {

        InputStreamReader streamReader = new InputStreamReader(body);
        try (BufferedReader lineReader = new BufferedReader(streamReader)) {
            StringBuilder responseBody = new StringBuilder();
            String line;
            while ((line = lineReader.readLine()) != null) {
                responseBody.append(line);
            }
            return responseBody.toString();
        } catch (IOException e) {
            throw new ApplicationAuthenticatorException("Error while reading response.", e);
        }
    }

    protected boolean isOauth2CodeParamExists(HttpServletRequest request) {

        return request.getParameter(OAUTH2_GRANT_TYPE_CODE) != null;
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
                && OAUTH2_LOGIN_TYPE.equals(getLoginType(request));
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

    protected String getTokenEndpoint(Map<String, String> authenticatorProperties) throws MisconfigurationException {

        String tokenUrl = authenticatorProperties.get(OAUTH2_TOKEN_URL);
        if (!StringUtils.isBlank(tokenUrl)) {
            return tokenUrl;
        } else {
            String errorMessage = "Error while retrieving properties. Token endpoint cannot be null.";
            logger.error(errorMessage);
            throw new MisconfigurationException(errorMessage);
        }
    }

    protected String getAuthorizationServerEndpoint(Map<String, String> authenticatorProperties)
            throws MisconfigurationException {

        String oAuthUrl = authenticatorProperties.get(OAUTH2_AUTHZ_URL);
        if (!StringUtils.isBlank(oAuthUrl)) {
            return oAuthUrl;
        } else {
            String errorMessage = "Error while retrieving properties. Authorization server endpoint cannot be null.";
            throw new MisconfigurationException(errorMessage);
        }
    }

    protected String getUserInfoEndpoint(Map<String, String> authenticatorProperties) throws MisconfigurationException {

        String userInfoUrl = authenticatorProperties.get(OAUTH2_USER_INFO_URL);
        if (!StringUtils.isBlank(userInfoUrl)) {
            return userInfoUrl;
        } else {
            String errorMessage = "Error while retrieving properties. User info endpoint cannot be null.";
            throw new MisconfigurationException(errorMessage);
        }
    }

    private Map<String, String> getAuthenticatorProperties(AuthenticationContext context)
            throws MisconfigurationException {

        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
        if (authenticatorProperties != null) {
            for (Map.Entry<String, String> entry : authenticatorProperties.entrySet()) {
                entry.setValue(StringUtils.trim(entry.getValue()));
            }
            return authenticatorProperties;
        } else {
            String errorMessage = "Error while retrieving properties. Authenticator Properties cannot be null.";
            throw new MisconfigurationException(errorMessage);
        }
    }

    private String getClientId(Map<String, String> authenticatorProperties) throws MisconfigurationException {

        String clientId = authenticatorProperties.get(CLIENT_ID);
        if (!StringUtils.isBlank(clientId)) {
            return clientId;
        } else {
            String errorMessage = "Error while retrieving properties. Client ID cannot be null.";
            throw new MisconfigurationException(errorMessage);
        }
    }

    private String getClientSecret(Map<String, String> authenticatorProperties) throws MisconfigurationException {

        String clientSecret = authenticatorProperties.get(CLIENT_SECRET);
        if (!StringUtils.isBlank(clientSecret)) {
            return clientSecret;
        } else {
            String errorMessage = "Error while retrieving properties. Client secret cannot be null.";
            throw new MisconfigurationException(errorMessage);
        }
    }

    private String getCallbackURL(Map<String, String> authenticatorProperties, String serverName, int serverPort)
            throws MisconfigurationException {

        String callbackURL = authenticatorProperties.get(CALLBACK_URL);
        if (StringUtils.isBlank(callbackURL)) {
            try {
                callbackURL = new URL(DEFAULT_PROTOCOL_IDENTIFIER, serverName, serverPort, CALLBACK_URL_DEFAULT)
                        .toString();
            } catch (MalformedURLException e) {
                throw new MisconfigurationException(e.getMessage(), e);
            }
            return callbackURL;
        }
        return callbackURL;
    }
}