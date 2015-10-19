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
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;

import org.apache.commons.codec.binary.Base64;
import org.scribe.model.OAuthRequest;
import org.scribe.model.Response;

import java.text.MessageFormat;

class UAAClient {

  private static final String OAUTH_ENDPOINT = "%s/oauth/";

  private static final String AUTHORIZE_ENDPOINT = OAUTH_ENDPOINT
      + "authorize?response_type=code&client_id=%s&redirect_uri=%s";
  private static final String TOKEN_ENDPOINT = OAUTH_ENDPOINT + "token";
  private static final String TOKEN_KEY_ENDPOINT = "%s/token_key";
  private static final String USERINFO_ENDPOINT = "%s/userinfo";

  private static final String GRANT_TYPE = "grant_type";
  private static final String BY_AUTHORIZATION_CODE = "authorization_code";

  private static final String ALG_ATTRIBUTE = "alg";
  private static final String VALUE_ATTRIBUTE = "value";
  private static final String PUBLIC_EXPONENT_ATTRIBUTE = "e";
  private static final String MODULUS_ATTRIBUTE = "n";
  private static final String ACCESS_TOKEN_ATTRIBUTE = "access_token";
  private static final String EXP_ATTRIBUTE = "exp";
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
  private final String tokenKeyEndpoint;
  private final String userInfoEndpoint;

  private final boolean verifySignatures;

  /**
   * Lazily initialized and may be updated from time to time
   * when token key is changed in UAA
   */
  private SignatureVerifier signatureVerifier;

  public UAAClient(String uaaServerUrl,
      String clientId,
      String clientSecret,
      boolean verifySignatures,
      String redirectUrl) {
    this.clientCredentials = BASIC_AUTHENTICATION + " "
      + encodeBase64(clientId + ":" + clientSecret);
    this.verifySignatures = verifySignatures;
    this.redirectUrl = redirectUrl;
    this.authorizationEndpoint = String.format(AUTHORIZE_ENDPOINT,
        uaaServerUrl, encode(clientId), encode(redirectUrl));
    this.accessTokenEndpoint = String.format(TOKEN_ENDPOINT, uaaServerUrl);
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
    if (authorizationCode == null) {
      throw new UAAClientException("Must provide an authorization code");
    }
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
    return parseAccessTokenResponse(response.getBody());
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
    if (accessToken == null) {
      throw new UAAClientException("Must provide an access token");
    }
    JsonObject jsonWebToken = toJsonWebToken(accessToken);
    long expiresAt = getLongAttribute(jsonWebToken, EXP_ATTRIBUTE, 0);
    String username = getAttribute(jsonWebToken, USER_NAME_ATTRIBUTE);
    if (username == null) {
      throw new UAAClientException(
          "Invalid token: missing or invalid 'user_name' attribute");
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
    if (accessToken == null) {
      throw new UAAClientException("Must provide an access token");
    }
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
    if (Strings.isNullOrEmpty(tokenResponse)) {
      throw new UAAClientException(
          "Can't extract a token from an empty string");
    }
    JsonObject json = getAsJsonObject(tokenResponse);
    String accessToken = getAttribute(json, ACCESS_TOKEN_ATTRIBUTE);
    if (accessToken == null) {
      throw new UAAClientException(
          "Can't extract a token: missing or invalid 'access_token' attribute");
    }
    return toAccessToken(accessToken);
  }

  @VisibleForTesting
  JsonObject toJsonWebToken(String accessToken)
      throws UAAClientException {
    String[] segments = accessToken.split("\\.");
    if (segments.length != 3) {
      throw new UAAClientException(
          "Invalid token: must be of the form 'header.token.signature'");
    }
    String claims = decodeBase64(segments[1]);
    if (verifySignatures) {
      String header = decodeBase64(segments[0]);
      String alg = getAttribute(getAsJsonObject(header), ALG_ATTRIBUTE);
      if (Strings.isNullOrEmpty(alg)) {
        throw new UAAClientException("Invalid token: missing \"alg\" attribute");
      }
      String signature = segments[2];
      String signedContent = segments[0] + "." + segments[1];
      verifySignature(signedContent, signature, alg);
    }
    return getAsJsonObject(claims);
  }

  @VisibleForTesting
  void verifySignature(String signedContent, String signature,
      String alg) throws UAAClientException {
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

  @VisibleForTesting
  String getAttribute(JsonObject json, String name) {
    JsonPrimitive prim = getAsJsonPrimitive(json, name);
    return prim != null && prim.isString() ? prim.getAsString() : null;
  }

  @VisibleForTesting
  long getLongAttribute(JsonObject json, String name, long defaultValue) {
    JsonPrimitive prim = getAsJsonPrimitive(json, name);
    return prim != null && prim.isNumber() ? prim.getAsLong() : defaultValue;
  }

  private JsonPrimitive getAsJsonPrimitive(JsonObject json, String name) {
    JsonElement attr = json.get(name);
    if (attr == null || !attr.isJsonPrimitive()) {
      return null;
    }
    return attr.getAsJsonPrimitive();
  }

  private JsonObject getAsJsonObject(String s) {
    JsonElement json = new JsonParser().parse(s);
    if (!json.isJsonObject()) {
      return new JsonObject();
    }
    return json.getAsJsonObject();
  }

  private String decodeBase64(String s) {
    return new String(Base64.decodeBase64(s), UTF_8);
  }

  private String encodeBase64(String s) {
    return new String(Base64.encodeBase64(s.getBytes(UTF_8)), US_ASCII);
  }
}
