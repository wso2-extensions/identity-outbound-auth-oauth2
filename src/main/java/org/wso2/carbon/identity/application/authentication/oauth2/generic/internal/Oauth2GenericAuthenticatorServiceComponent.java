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
package org.wso2.carbon.identity.application.authentication.oauth2.generic.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.oauth2.generic.Oauth2GenericAuthenticator;

import java.util.Hashtable;

@Component(name = "Oauth2GenericAuthenticatorServiceComponent", immediate = true)
public class Oauth2GenericAuthenticatorServiceComponent {

    private static final Log logger = LogFactory.getLog(Oauth2GenericAuthenticatorServiceComponent.class);

    @Activate
    protected void activate(ComponentContext context) {

        try {
            Oauth2GenericAuthenticator oauthAuthenticator = new Oauth2GenericAuthenticator();
            Hashtable<String, String> props = new Hashtable<>();
            context.getBundleContext().registerService(ApplicationAuthenticator.class.getName(), oauthAuthenticator,
                    props);
            if (logger.isDebugEnabled()) {
                logger.debug("----Oauth Authenticator bundle is activated----");
            }

        } catch (Throwable e) {
            logger.error("----Error while activating Oauth authenticator----", e);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext context) {

        if (logger.isDebugEnabled()) {
            logger.debug("----Oauth Authenticator bundle is deactivated----");
        }
    }

}
