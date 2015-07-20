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

import static java.nio.charset.StandardCharsets.US_ASCII;
import static org.apache.commons.codec.binary.Base64.encodeBase64URLSafe;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.text.MessageFormat;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

class HMACSHA256SignatureVerifier implements SignatureVerifier {

  private static final String HS256 = "HS256";
  private static final String HMAC_SHA256 = "HMACSHA256";

  private final SecretKey secretKey;

  public HMACSHA256SignatureVerifier(String secret) {
    secretKey = new SecretKeySpec(secret.getBytes(US_ASCII), HMAC_SHA256);
  }

  @Override
  public boolean verify(String content, String signature) {
    Mac mac = null;
    try {
      mac = Mac.getInstance(HMAC_SHA256);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(
          "Runtime does not support HMACSHA256 signatures", e);
    }
    try {
      mac.init(secretKey);
    } catch (InvalidKeyException e) {
      throw new IllegalArgumentException(MessageFormat.format(
          "Invalid HMACSHA256 secret: {0}", secretKey), e);
    }
    byte[] digest = mac.doFinal(content.getBytes(US_ASCII));
    String actualSignature = new String(encodeBase64URLSafe(digest), US_ASCII);
    return signature.equals(actualSignature);
  }

  @Override
  public boolean supports(String algorithm) {
    return HS256.equalsIgnoreCase(algorithm)
        || HMAC_SHA256.equalsIgnoreCase(algorithm);
  }

}
