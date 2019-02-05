load("//tools/bzl:junit.bzl", "junit_tests")
load(
    "//tools/bzl:plugin.bzl",
    "PLUGIN_DEPS",
    "PLUGIN_TEST_DEPS",
    "gerrit_plugin",
)

TEST_SRCS = "src/test/java/**/*Test.java"

TEST_DEPS = PLUGIN_DEPS + PLUGIN_TEST_DEPS + [
    ":cfoauth__plugin",
    "@scribe//jar",
    "@commons_codec//jar",
]

gerrit_plugin(
    name = "cfoauth",
    srcs = glob(["src/main/java/**/*.java"]),
    manifest_entries = [
        "Gerrit-PluginName: cfoauth",
        "Gerrit-Module: com.googlesource.gerrit.plugins.cfoauth.OAuthModule",
        "Gerrit-HttpModule: com.googlesource.gerrit.plugins.cfoauth.HttpModule",
        "Gerrit-InitStep: com.googlesource.gerrit.plugins.cfoauth.InitOAuthConfig",
        "Implementation-Title: Cloud Foundry UAA OAuth 2.0 Authentication Provider",
        "Implementation-URL: https://gerrit-review.googlesource.com/#/admin/projects/plugins/cfoauth",
    ],
    resources = glob(["src/main/resources/**/*"]),
    deps = [
        "@commons_codec//jar:neverlink",
        "@scribe//jar",
    ],
)

java_library(
    name = "testutils",
    testonly = 1,
    srcs = glob(
        include = ["src/test/java/**/*.java"],
        exclude = [TEST_SRCS],
    ),
    deps = TEST_DEPS,
)

junit_tests(
    name = "cfoauth_tests",
    testonly = 1,
    srcs = glob([TEST_SRCS]),
    tags = ["cfoauth"],
    deps = TEST_DEPS + [
        ":testutils",
    ],
)
