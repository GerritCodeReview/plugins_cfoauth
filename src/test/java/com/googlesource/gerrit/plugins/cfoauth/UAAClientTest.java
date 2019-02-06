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

import static org.junit.Assert.*;
import static com.googlesource.gerrit.plugins.cfoauth.JsonUtils.getAttribute;
import static com.googlesource.gerrit.plugins.cfoauth.JsonUtils.getLongAttribute;

import com.google.gson.JsonObject;

import org.junit.Before;
import org.junit.Test;

public class UAAClientTest {

  private static final String HS256_TEST_TOKEN =
      "eyJhbGciOiJIUzI1NiJ9.eyJqdGkiOiI4MWI4M2RhNy0yZmI2LTQ4OTUtYTM5ZS0zZ"
      + "TFjZWEzNzQ2ZDkiLCJzdWIiOiJmNmM1YTgxMi0yNWM2LTQ5ZjItOTJiMS0yYjQ5N"
      + "mRjOTAyNTUiLCJzY29wZSI6WyJvcGVuaWQiXSwiY2xpZW50X2lkIjoiZ2Vycml0L"
      + "WlkIiwiY2lkIjoiZ2Vycml0LWlkIiwiYXpwIjoiZ2Vycml0LWlkIiwiZ3JhbnRfd"
      + "HlwZSI6ImF1dGhvcml6YXRpb25fY29kZSIsInVzZXJfaWQiOiJmNmM1YTgxMi0yN"
      + "WM2LTQ5ZjItOTJiMS0yYjQ5NmRjOTAyNTUiLCJ1c2VyX25hbWUiOiJtYXJpc3NhI"
      + "iwiZW1haWwiOiJtYXJpc3NhQHRlc3Qub3JnIiwicmV2X3NpZyI6IjkwZGQzNTNlI"
      + "iwiaWF0IjoxNDM2MTg5NzMyLCJleHAiOjE0MzYyMzI5MzIsImlzcyI6Imh0dHA6L"
      + "y9sb2NhbGhvc3Q6ODA4MC91YWEvb2F1dGgvdG9rZW4iLCJ6aWQiOiJ1YWEiLCJhd"
      + "WQiOlsiZ2Vycml0LWlkIiwib3BlbmlkIl19.ynnx6J9CO-jnKETDn4DSEdvWMZkC"
      + "2mTynnhgYL-TyaU";

  private static final String[] HS256_TOKEN_PARTS =
      HS256_TEST_TOKEN.split("\\.");

  private static final String HS256_SIGNED_CONTENT =
      HS256_TOKEN_PARTS[0] + "." + HS256_TOKEN_PARTS[1];
  private static final String HS256_SIGNATURE =
      HS256_TOKEN_PARTS[2];
  private static final String HS256_INVALID_SIGNATURE =
      ".dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";


  private static final String HS256_TOKEN_INVALID_HEADER = ""
      + "foo" + HS256_TOKEN_PARTS[1] + "." + HS256_TOKEN_PARTS[2];
  private static final String HS256_TOKEN_INVLID_CLAIMS =
      HS256_TOKEN_PARTS[0] + ".foo." + HS256_TOKEN_PARTS[2];
  private static final String HS256_TOKEN_INVALID_SIGNATURE =
      HS256_TOKEN_PARTS[0] + "." + HS256_TOKEN_PARTS[1]
          + HS256_INVALID_SIGNATURE;

  private static final String HS256_ACCESS_TOKEN_RESPONSE = "{"
      + "\"access_token\":\"" + HS256_TEST_TOKEN + "\","
      + "\"token_type\":\"bearer\","
      + "\"expires_in\":3600}";

  private static final String MISSING_ACCESS_TOKEN_ATTRIBUTE= "{"
      + "\"access_token1\":\"" + HS256_TEST_TOKEN + "\"}";

  private static final String INVALID_TOKEN_ATTRIBUTE= "{"
      + "\"access_token\":\"" + HS256_TOKEN_INVALID_SIGNATURE + "\"}";

  private static final String UAA_SERVER_URL = "http://uaa.example.org/uaa";
  private static final String CLIENT_ID = "gerrit";
  private static final String CLIENT_SECRET = "gerritsecret";
  private static final String REDIRECT_URL = "http://gerrit.example.org/oauth";

  private static final String TOKEN_KEY = "tokenkey";

  private static class UAATestClient extends UAAClient {

    public UAATestClient() {
      super(UAA_SERVER_URL, CLIENT_ID, CLIENT_SECRET, true, false,
          REDIRECT_URL);
    }

    @Override
    SignatureVerifier getSignatureVerifier(String alg, boolean refresh)
        throws UAAClientException {
      return new HMACSHA256SignatureVerifier(TOKEN_KEY);
    }
  }

  private UAAClient client;

  @Before
  public void setup() throws Exception {
    client = new UAATestClient();
  }

  @Test
  public void testGetAuthorizationUrl() throws Exception {
    assertEquals("http://uaa.example.org/uaa/oauth/authorize?"
        + "response_type=code&client_id=gerrit&redirect_uri="
        + "http%3A%2F%2Fgerrit.example.org%2Foauth",
        client.getAuthorizationUrl());
  }

  @Test
  public void testToJsonWebToken() throws Exception {
    JsonObject jsonWebToken = client.toJsonWebToken(HS256_TEST_TOKEN);
    assertEquals("marissa", getAttribute(jsonWebToken, "user_name"));
    assertEquals("marissa@test.org", getAttribute(jsonWebToken, "email"));
    assertEquals(1436232932L, getLongAttribute(jsonWebToken, "exp", 0));
  }

  @Test(expected = UAAClientException.class)
  public void testToJsonWebTokenInvalidToken() throws Exception {
    client.toJsonWebToken("foobar");
  }

  @Test(expected = UAAClientException.class)
  public void testToJsonWebTokenInvalidPrefix() throws Exception {
    client.toJsonWebToken(HS256_TOKEN_INVALID_HEADER);
  }

  @Test(expected = UAAClientException.class)
  public void testToJsonWebTokenInvalidClaims() throws Exception {
    client.toJsonWebToken(HS256_TOKEN_INVLID_CLAIMS);
  }

  @Test(expected = UAAClientException.class)
  public void testToJsonWebTokenInvalidSignature() throws Exception {
    client.toJsonWebToken(HS256_TOKEN_INVALID_SIGNATURE);
  }

  @Test
  public void testGetAsAccessToken() throws Exception {
    AccessToken accessToken = client.toAccessToken(HS256_TEST_TOKEN,
        HS256_ACCESS_TOKEN_RESPONSE);
    assertHS266AccessToken(accessToken);
  }

  @Test
  public void testVerifySignature() throws Exception {
    client.verifySignature(HS256_SIGNED_CONTENT, HS256_SIGNATURE, "HS256");
  }

  @Test(expected = UAAClientException.class)
  public void testVerifyInvalidSignature() throws Exception {
    client.verifySignature(HS256_SIGNED_CONTENT, HS256_INVALID_SIGNATURE,
        "HS256");
  }

  @Test
  public void testParseAccessTokenResponse() throws Exception {
    AccessToken accessToken = client.parseAccessTokenResponse(
        HS256_ACCESS_TOKEN_RESPONSE);
    assertHS266AccessToken(accessToken);
  }

  @Test(expected = UAAClientException.class)
  public void testParseAccessTokenResponseMissingAccessTokenAttribute()
      throws Exception {
    client.parseAccessTokenResponse(MISSING_ACCESS_TOKEN_ATTRIBUTE);
  }

  @Test(expected = UAAClientException.class)
  public void testParseAccessTokenResponseInvalidTokenAttribute()
      throws Exception {
    client.parseAccessTokenResponse(INVALID_TOKEN_ATTRIBUTE);
  }

  private void assertHS266AccessToken(AccessToken accessToken) {
    assertEquals(HS256_TEST_TOKEN, accessToken.getValue());
    assertEquals(1436232932L, accessToken.getExpiresAt());
    UserInfo userInfo = accessToken.getUserInfo();
    assertEquals("external:marissa", userInfo.getExternalId());
    assertEquals("marissa", userInfo.getUserName());
    assertEquals("marissa@test.org", userInfo.getEmailAddress());
  }
}
