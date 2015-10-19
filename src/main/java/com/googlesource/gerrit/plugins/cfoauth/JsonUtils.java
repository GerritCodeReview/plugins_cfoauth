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

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;

public class JsonUtils {

  public static String getAttribute(JsonObject json, String name) {
    JsonPrimitive prim = getAsJsonPrimitive(json, name);
    return prim != null && prim.isString() ? prim.getAsString() : null;
  }

  public static long getLongAttribute(JsonObject json, String name,
      long defaultValue) {
    JsonPrimitive prim = getAsJsonPrimitive(json, name);
    return prim != null && prim.isNumber() ? prim.getAsLong() : defaultValue;
  }

  public static JsonPrimitive getAsJsonPrimitive(JsonObject json, String name) {
    JsonElement attr = json.get(name);
    if (attr == null || !attr.isJsonPrimitive()) {
      return null;
    }
    return attr.getAsJsonPrimitive();
  }

  public static JsonObject getAsJsonObject(String s) {
    JsonElement json = new JsonParser().parse(s);
    if (!json.isJsonObject()) {
      return new JsonObject();
    }
    return json.getAsJsonObject();
  }

}
