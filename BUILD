load("//tools/bzl:junit.bzl", "junit_tests")
load(
    "//tools/bzl:plugin.bzl",
    "gerrit_plugin",
    "PLUGIN_DEPS",
    "PLUGIN_TEST_DEPS",
)

gerrit_plugin(
    name = "cfoauth",
    srcs = glob(["src/main/java/**/*.java"]),
    resources = glob(["src/main/resources/**/*"]),
    manifest_entries = [
        "Gerrit-PluginName: cfoauth",
        "Gerrit-Module: com.googlesource.gerrit.plugins.cfoauth.OAuthModule",
        "Gerrit-HttpModule: com.googlesource.gerrit.plugins.cfoauth.HttpModule",
        "Gerrit-InitStep: com.googlesource.gerrit.plugins.cfoauth.InitOAuthConfig",
        "Implementation-Title: Cloud Foundry UAA OAuth 2.0 Authentication Provider",
        "Implementation-URL: https://gerrit-review.googlesource.com/#/admin/projects/plugins/cfoauth",
    ],
    deps = [
        "//plugins/cfoauth/lib:scribe",
    ],
    provided_deps = [
        "//lib:guava",
        "//lib:gson",
        "//plugins/cfoauth/lib:commons-codec",
    ],
)

junit_tests(
    name = "cfoauth_tests",
    srcs = glob(["src/test/java/**/*.java"]),
    tags = ["cfoauth"],
    deps = PLUGIN_DEPS + PLUGIN_TEST_DEPS + [
        ":cfoauth__plugin",
        "//plugins/cfoauth/lib:scribe",
        "//lib:guava",
        "//lib:gson",
        "//plugins/cfoauth/lib:commons-codec",
    ],
)
