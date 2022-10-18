# identity-outbound-auth-oauth2
Oauth2.0 Outbound Authentication Connector

>`identity-outbound-auth-oauth2` v1.0.5 onward gives more flexibility in defining the user id.

Follow the steps given below to set this up.

1. Log in to the [Management Console](https://is.docs.wso2.com/en/5.9.0/setup/getting-started-with-the-management-console/).

2. In the **Identity Providers** section under the **Main** tab of the management console, click **List**.

3. Select the identity provider which is required to define the user id, and Click **Edit**.

4. Navigate to the **Basic Claim Configuration** section under the **Claim Configuration** tab.

5. Select `Define Custom Claim Dialect` as **Claim mapping Dialect**.

6. Add the new claim mapping for user id by clicking **Add Claim Mapping**.

7. Config the `User ID Claim URI` as the above defined user id claim.

8. Click on **Update**.

The following example shows the claim mapping configuration where the `Identity Provider Claim URI` for user id is `id` in IDP.

<img width="1383" alt="Screenshot 2022-10-18 at 3 00 36 PM" src="https://user-images.githubusercontent.com/42811248/196425160-fda55f72-bcb0-4d11-914a-47a98c4570c0.png">
