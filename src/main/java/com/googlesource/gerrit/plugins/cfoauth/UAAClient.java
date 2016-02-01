// Copyright (C) 2015 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.googlesource.gerrit.plugins.cfoauth;

import static com.googlesource.gerrit.plugins.cfoauth.JsonUtils.*;

import static java.net.HttpURLConnection.HTTP_OK;
import static java.nio.charset.StandardCharsets.US_ASCII;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.scribe.model.OAuthConstants.CODE;
import static org.scribe.model.OAuthConstants.REDIRECT_URI;
import static org.scribe.model.Verb.GET;
import static org.scribe.model.Verb.POST;
import static org.scribe.utils.OAuthEncoder.encode;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Strings;
import com.google.gson.JsonObject;

import org.apache.commons.codec.binary.Base64;
import org.scribe.model.OAuthRequest;
import org.scribe.model.Response;

import java.text.MessageFormat;
import java.util.Locale;

class UAAClient {

  private static final String OAUTH_ENDPOINT = "%s/oauth/";

  private static final String AUTHORIZE_ENDPOINT = OAUTH_ENDPOINT
      + "authorize?response_type=code&client_id=%s&redirect_uri=%s";
  private static final String TOKEN_ENDPOINT = OAUTH_ENDPOINT + "token";
  private static final String CHECK_TOKEN_ENDPOINT = "%s/check_token";
  private static final String TOKEN_KEY_ENDPOINT = "%s/token_key";
  private static final String USERINFO_ENDPOINT = "%s/userinfo";

  private static final String GRANT_TYPE = "grant_type";
  private static final String BY_AUTHORIZATION_CODE = "authorization_code";
  private static final String BY_PASSWORD = "password";

  private static final String USERNAME_PARAMETER = "username";
  private static final String PASSWORD_PARAMETER = "password";
  private static final String TOKEN_PARAMETER = "token";

  private static final String ALG_ATTRIBUTE = "alg";
  private static final String VALUE_ATTRIBUTE = "value";
  private static final String PUBLIC_EXPONENT_ATTRIBUTE = "e";
  private static final String MODULUS_ATTRIBUTE = "n";
  private static final String ACCESS_TOKEN_ATTRIBUTE = "access_token";
  private static final String EXP_ATTRIBUTE = "exp";
  private static final String SUB_ATTRIBUTE = "sub";
  private static final String USER_NAME_ATTRIBUTE = "user_name";
  private static final String EMAIL_ATTRIBUTE = "email";
  private static final String NAME_ATTRIBUTE = "name";

  private static final String AUTHORIZATION_HEADER = "Authorization";
  private static final String BASIC_AUTHENTICATION = "Basic";
  private static final String BEARER_AUTHENTICATION = "Bearer";

  private final String clientCredentials;
  private final String redirectUrl;

  private final String authorizationEndpoint;
  private final String accessTokenEndpoint;
  private final String checkTokenEndpoint;
  private final String tokenKeyEndpoint;
  private final String userInfoEndpoint;

  private final boolean verifySignatures;
  private final boolean userNameToLowerCase;

  /**
   * Lazily initialized and may be updated from time to time
   * when token key is changed in UAA
   */
  private SignatureVerifier signatureVerifier;

  public UAAClient(String uaaServerUrl,
      String clientId,
      String clientSecret,
      boolean verifySignatures,
      boolean userNameToLowerCase,
      String redirectUrl) {
    this.clientCredentials = BASIC_AUTHENTICATION + " "
      + encodeBase64(clientId + ":" + clientSecret);
    this.verifySignatures = verifySignatures;
    this.userNameToLowerCase = userNameToLowerCase;
    this.redirectUrl = redirectUrl;
    this.authorizationEndpoint = String.format(AUTHORIZE_ENDPOINT,
        uaaServerUrl, encode(clientId), encode(redirectUrl));
    this.accessTokenEndpoint = String.format(TOKEN_ENDPOINT, uaaServerUrl);
    this.checkTokenEndpoint = String.format(CHECK_TOKEN_ENDPOINT, uaaServerUrl);
    this.tokenKeyEndpoint = String.format(TOKEN_KEY_ENDPOINT, uaaServerUrl);
    this.userInfoEndpoint = String.format(USERINFO_ENDPOINT, uaaServerUrl);
  }

  /**
   * Returns the authorization grant endpoint of the UAA server.
   */
  public String getAuthorizationUrl() {
    return authorizationEndpoint;
  }

  /**
   * Retrieves an access token from the UAA server providing an
   * authorization code following the "Authorization Code Grant"
   * scheme of RFC6749 section 4.1.
   *
   * @param authorizationCode a previously obtained authorization code.
   * @return an access token.
   *
   * @throws UAAClientException if the UAA request failed.
   */
  public AccessToken getAccessToken(String authorizationCode)
      throws UAAClientException {
    OAuthRequest request = new OAuthRequest(POST, accessTokenEndpoint);
    request.addHeader(AUTHORIZATION_HEADER, clientCredentials);
    request.addBodyParameter(GRANT_TYPE, BY_AUTHORIZATION_CODE);
    request.addBodyParameter(CODE, authorizationCode);
    request.addBodyParameter(REDIRECT_URI, redirectUrl);
    Response response = request.send();
    if (response.getCode() != HTTP_OK) {
      throw new UAAClientException(MessageFormat.format(
          "POST /oauth/token failed with status {0}", response.getCode()));
    }
    String tokenResponse = response.getBody();
    if (Strings.isNullOrEmpty(tokenResponse)) {
      throw new UAAClientException(
          "POST /oauth/token failed: invalid access token response");
    }
    return parseAccessTokenResponse(tokenResponse);
  }

  /**
   * Retrieves an access token from the UAA server providing a user name
   * and password following the "Resource Owner Password Credentials Grant"
   * scheme of RFC6749 section 4.3.
   *
   * @param username the name of the resource owner.
   * @param password the password of the resource owner.
   * @return an access token.
   *
   * @throws UAAClientException if the UAA request failed.
   */
  public AccessToken getAccessToken(String username, String password)
      throws UAAClientException{
    if (username == null || password == null) {
      throw new UAAClientException("Must provide user name and password");
    }
    OAuthRequest request = new OAuthRequest(POST, accessTokenEndpoint);
    request.addHeader(AUTHORIZATION_HEADER, clientCredentials);
    request.addQuerystringParameter(GRANT_TYPE, BY_PASSWORD);
    request.addQuerystringParameter(USERNAME_PARAMETER, username);
    request.addQuerystringParameter(PASSWORD_PARAMETER, password);
    Response response = request.send();
    if (response.getCode() == 401) {
      throw new UAAClientException("Invalid username or password");
    }
    if (response.getCode() != 200) {
      throw new UAAClientException(MessageFormat.format(
          "POST /oauth/token failed with status {0}", response.getCode()));
    }
    String tokenResponse = response.getBody();
    if (Strings.isNullOrEmpty(tokenResponse)) {
      throw new UAAClientException(
          "POST /oauth/token failed: invalid access token response");
    }
    return parseAccessTokenResponse(tokenResponse);
  }

  /**
   * Verifies the given access token with the UAA server.
   * This method passes the access token to the <tt>/check_token</tt>
   * endpoint of the UAA server.
   *
   * @param accessToken the access token to verify.
   * @return <code>true</code> if the token could be verified.
   *
   * @throws UAAClientException if the UAA request failed.
   */
  public boolean verifyAccessToken(String accessToken)
      throws UAAClientException {
    OAuthRequest request = new OAuthRequest(POST, checkTokenEndpoint);
    request.addHeader(AUTHORIZATION_HEADER, clientCredentials);
    request.addBodyParameter(TOKEN_PARAMETER, accessToken);
    Response response = request.send();
    if (response.getCode() == 400) {
      return false;
    }
    if (response.getCode() != 200) {
      throw new UAAClientException(MessageFormat.format(
          "POST /check_token failed with status {0}", response.getCode()));
    }
    return true;
  }

  /**
   * Checks if the given access token is valid and is owned by the given user.
   *
   * @param username the name of the token owner.
   * @param accessToken the access token to check.
   *
   * @return <code>true</code> if the token is valid and belongs to
   * the given user.
   */
  public boolean isAccessTokenForUser(String username, String accessToken) {
    try {
      JsonObject jsonWebToken = toJsonWebToken(accessToken);
      return equalsAdjustCase(username,
          getAttribute(jsonWebToken, USER_NAME_ATTRIBUTE));
    } catch (UAAClientException e) {
      return false;
    }
  }

  /**
   * Checks if the given access token is valid and is owned by the given client.
   *
   * @param clientname the name of the client.
   * @param accessToken the access token to check.
   *
   * @return <code>true</code> if the token is valid and belongs to
   * the given client.
   */
  public boolean isAccessTokenForClient(String clientname, String accessToken) {
    try {
      JsonObject jsonWebToken = toJsonWebToken(accessToken);
      return getAttribute(jsonWebToken, USER_NAME_ATTRIBUTE) == null &&
          equalsAdjustCase(clientname,
              getAttribute(jsonWebToken, SUB_ATTRIBUTE));
    } catch (UAAClientException e) {
      return false;
    }
  }

  /**
   * Converts an access token given as string represenation
   * into an {@link AccessToken}.
   *
   * @param accessToken the access token to convert.
   * @return the <code>AccessToken</code> corressponding to the
   * given access token.
   *
   * @throws UAAClientException if the given access token is not
   * valid or could not be converted into an <code>AccessToken</code>.
   */
  public AccessToken toAccessToken(String accessToken)
      throws UAAClientException {
    JsonObject jsonWebToken = toJsonWebToken(accessToken);
    long expiresAt = getLongAttribute(jsonWebToken, EXP_ATTRIBUTE, 0);
    String username = getAttribute(jsonWebToken, USER_NAME_ATTRIBUTE);
    if (username == null) {
      throw new UAAClientException(
          "Invalid token: missing or invalid 'user_name' attribute");
    }
    if (userNameToLowerCase) {
      username = lowercase(username);
    }
    String emailAddress = getAttribute(jsonWebToken, EMAIL_ATTRIBUTE);
    if (emailAddress == null) {
      throw new UAAClientException(
          "Invalid token: missing or invalid 'email' attribute");
    }
    return new AccessToken(accessToken, username, emailAddress, expiresAt);
  }

  /**
   * Retrieves the display name of the access token owner.
   * This method queries the <tt>/userinfo</tt> endpoint of the
   * UAA server and requires the scope <tt>openid</tt>.
   *
   * @param accessToken the access token.
   * @return the display name of the access token owner.
   *
   * @throws UAAClientException if the UAA request failed.
   */
  public String getDisplayName(String accessToken) {
    OAuthRequest request = new OAuthRequest(GET, userInfoEndpoint);
    request.addHeader(AUTHORIZATION_HEADER,
        BEARER_AUTHENTICATION + " " + accessToken);
    Response response = request.send();
    if (response.getCode() != HTTP_OK) {
      throw new UAAClientException(MessageFormat.format(
          "GET /userinfo failed with status {0}", response.getCode()));
    }
    JsonObject userInfoResponse = getAsJsonObject(response.getBody());
    return getAttribute(userInfoResponse, NAME_ATTRIBUTE);
  }

  @VisibleForTesting
  AccessToken parseAccessTokenResponse(String tokenResponse)
      throws UAAClientException {
    return toAccessToken(getAccessTokenAttribute(tokenResponse));
  }

  @VisibleForTesting
  JsonObject toJsonWebToken(String accessToken) throws UAAClientException {
    String[] segments = getSegments(accessToken);
    if (verifySignatures) {
      verifySignature(segments);
    }
    return getAsJsonObject(decodeBase64(segments[1]));
  }

  private String[] getSegments(String accessToken) throws UAAClientException {
    String[] segments = accessToken.split("\\.");
    if (segments.length != 3) {
      throw new UAAClientException(
          "Invalid token: must be of the form 'header.token.signature'");
    }
    return segments;
  }

  private void verifySignature(String[] segments) throws UAAClientException {
    String header = decodeBase64(segments[0]);
    String alg = getAttribute(getAsJsonObject(header), ALG_ATTRIBUTE);
    if (Strings.isNullOrEmpty(alg)) {
      throw new UAAClientException("Invalid token: missing \"alg\" attribute");
    }
    String signature = segments[2];
    String signedContent = segments[0] + "." + segments[1];
    verifySignature(signedContent, signature, alg);
  }

  @VisibleForTesting
  void verifySignature(String signedContent, String signature, String alg)
      throws UAAClientException {
    SignatureVerifier verifier = getSignatureVerifier(alg, false);
    if (!verifier.verify(signedContent, signature)) {
      // If the signature is invalid, maybe the secret has changed
      // in the UAA? Obtain a fresh signature verifier and try again
      verifier = getSignatureVerifier(alg, true);
      if (!verifier.verify(signedContent, signature)) {
        throw new UAAClientException(MessageFormat.format(
            "Invalid token signature ''{0}''", signature));
      }
    }
  }

  @VisibleForTesting
  synchronized SignatureVerifier getSignatureVerifier(String alg,
      boolean refresh) throws UAAClientException {
    if (signatureVerifier == null || refresh) {
      signatureVerifier = createSignatureVerifier();
    }
    if (!signatureVerifier.supports(alg)) {
      throw new UAAClientException(MessageFormat.format(
          "Invalid token: unexpected signature algorithm ''{0}''", alg));
    }
    return signatureVerifier;
  }

  private SignatureVerifier createSignatureVerifier()
      throws UAAClientException {
    OAuthRequest request = new OAuthRequest(GET, tokenKeyEndpoint);
    request.addHeader(AUTHORIZATION_HEADER, clientCredentials);
    Response response = request.send();
    if (response.getCode() != HTTP_OK) {
      throw new UAAClientException(MessageFormat.format(
          "GET /token_key failed with status {0}", response.getCode()));
    }
    JsonObject content = getAsJsonObject(response.getBody());
    String alg = getAttribute(content, ALG_ATTRIBUTE);
    if (Strings.isNullOrEmpty(alg)) {
      throw new UAAClientException(
          "GET /uaa/token_key failed: missing \"alg\" attribute");
    }
    if ("HMACSHA256".equals(alg)) {
      return new HMACSHA256SignatureVerifier(
          getAttribute(content, VALUE_ATTRIBUTE));
    } else if ("SHA256withRSA".equals(alg)) {
      return new SHA265WithRSASignatureVerifier(
          getAttribute(content, MODULUS_ATTRIBUTE),
          getAttribute(content, PUBLIC_EXPONENT_ATTRIBUTE));
    }
    throw new UAAClientException(MessageFormat.format(
        "Unsupported signature algorithm ''{0}''", alg));
  }

  private String getAccessTokenAttribute(String tokenResponse)
      throws UAAClientException {
    JsonObject json = getAsJsonObject(tokenResponse);
    String accessToken = getAttribute(json, ACCESS_TOKEN_ATTRIBUTE);
    if (accessToken == null) {
      throw new UAAClientException(
          "Can't extract a token: missing or invalid 'access_token' attribute");
    }
    return accessToken;
  }

  private boolean equalsAdjustCase(String left, String right) {
    return userNameToLowerCase
        ? lowercase(left).equals(lowercase(right))
        : left.equals(right);
  }

  private static String lowercase(String s) {
    return s.toLowerCase(Locale.US);
  }

  private String decodeBase64(String s) {
    return new String(Base64.decodeBase64(s), UTF_8);
  }

  private String encodeBase64(String s) {
    return new String(Base64.encodeBase64(s.getBytes(UTF_8)), US_ASCII);
  }
}
