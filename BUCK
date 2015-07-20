include_defs('//bucklets/gerrit_plugin.bucklet')
include_defs('//bucklets/maven_jar.bucklet')
define_license('scribe')

gerrit_plugin(
  name = 'cfoauth',
  srcs = glob(['src/main/java/**/*.java']),
  resources = glob(['src/main/**/*']),
  manifest_entries = [
    'Gerrit-PluginName: cfoauth',
    'Gerrit-ApiType: plugin',
    'Gerrit-ApiVersion: 2.12-SNAPSHOT',
    'Gerrit-HttpModule: com.googlesource.gerrit.plugins.cfoauth.HttpModule',
    'Gerrit-InitStep: com.googlesource.gerrit.plugins.cfoauth.InitOAuthConfig',
    'Implementation-Title: Cloud Foundry UAA OAuth 2.0 Authentication Provider',
    'Implementation-URL: https://gerrit-review.googlesource.com/#/admin/projects/plugins/cfoauth',
  ],
  deps = [
    ':scribe'
  ],
  provided_deps = [
    '//lib:guava',
    '//lib:gson',
    '//lib/commons:codec'
  ],
)

# this is required for bucklets/tools/eclipse/project.py to work
java_library(
  name = 'classpath',
  deps = [':cfoauth__plugin'],
)

java_test(
  name = 'cfoauth_tests',
  srcs = glob(['src/test/java/**/*.java']),
  labels = ['cfoauth'],
  deps = [
    ':cfoauth__plugin',
    ':scribe',
    '//lib:junit',
    '//lib:guava',
    '//lib:gson',
    '//lib/commons:codec'
  ],
)

maven_jar(
  name = 'scribe',
  id = 'org.scribe:scribe:1.3.7',
  sha1 = '583921bed46635d9f529ef5f14f7c9e83367bc6e',
  license = 'scribe',
  local_license = True,
)
