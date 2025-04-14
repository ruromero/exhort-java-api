/*
 * Copyright © 2023 Red Hat, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.redhat.exhort.providers;

import com.redhat.exhort.tools.Ecosystem;
import com.redhat.exhort.tools.Operations;
import java.nio.file.Path;
import java.util.regex.Pattern;

/**
 * Concrete implementation of the {@link JavaScriptProvider} used for converting dependency trees
 * for yarn v2 projects (package.json) into a SBOM content for Stack analysis or Component analysis.
 */
public final class JavaScriptYarnProvider extends JavaScriptProvider {

  public static final String LOCK_FILE = "yarn.lock";
  public static final String CMD_NAME = "yarn";
  public static final String ENV_YARN_HOME = "YARN_HOME";

  private static final Pattern versionPattern = Pattern.compile("^([0-9]+)\\.");

  private enum YarnVersion {
    Classic, // 1.x - Follow traditional Node.js patterns
    Berry // 2.x and above
  }

  private YarnVersion version;

  public JavaScriptYarnProvider(Path manifest) {
    super(manifest, Ecosystem.Type.YARN, CMD_NAME);
    this.version = resolveVersion(manifest);
  }

  @Override
  protected final String lockFileName() {
    return LOCK_FILE;
  }

  @Override
  protected String pathEnv() {
    return ENV_YARN_HOME;
  }

  @Override
  protected String[] updateLockFileCmd(Path manifestDir) {
    switch (version) {
      case Classic:
        return installClassicCmd(manifestDir);
      case Berry:
        return installBerryCmd(manifestDir);
      default:
        throw new IllegalStateException("Unexpected Yarn version: " + version);
    }
  }

  private String[] installClassicCmd(Path manifestDir) {
    if (manifestDir != null) {
      return new String[] {
        packageManager(), "--cwd", manifestDir.toString(), "install", "--frozen-lockfile"
      };
    }
    return new String[] {packageManager(), "install", "--frozen-lockfile"};
  }

  private String[] installBerryCmd(Path manifestDir) {
    if (manifestDir != null) {
      return new String[] {
        packageManager(), "--cwd", manifestDir.toString(), "install", "--immutable"
      };
    }
    return new String[] {packageManager(), "install", "--immutable"};
  }

  @Override
  protected String[] listDepsCmd(boolean includeTransitive, Path manifestDir) {
    switch (version) {
      case Classic:
        return listDepsClassicCmd(includeTransitive, manifestDir);
      case Berry:
        return listDepsBerryCmd(includeTransitive, manifestDir);
      default:
        throw new IllegalStateException("Unexpected Yarn version: " + version);
    }
  }

  private String[] listDepsBerryCmd(boolean includeTransitive, Path manifestDir) {
    if (manifestDir != null) {
      return new String[] {
        cmd,
        "--cwd",
        manifestDir.toString(),
        "info",
        includeTransitive ? "--recursive" : "--all",
        "--json",
      };
    }
    return new String[] {
      cmd, "info", includeTransitive ? "--recursive" : "--all", "--json",
    };
  }

  private String[] listDepsClassicCmd(boolean includeTransitive, Path manifestDir) {
    if (manifestDir != null) {
      return new String[] {
        cmd,
        "--cwd",
        manifestDir.toString(),
        "list",
        includeTransitive ? "--depth=-1" : "--depth=0",
        "--prod",
        "--frozen-lockfile",
        "--json",
      };
    }
    return new String[] {
      cmd,
      "list",
      includeTransitive ? "--depth=-1" : "--depth=0",
      "--prod",
      "--frozen-lockfile",
      "--json",
    };
  }

  private YarnVersion resolveVersion(Path manifest) {
    var output = Operations.runProcessGetOutput(manifest.getParent(), new String[] {cmd, "-v"});
    var matcher = versionPattern.matcher(output);
    if (matcher.find()) {
      var majorVersion = Integer.parseInt(matcher.group(1));
      switch (majorVersion) {
        case 1:
          return YarnVersion.Classic;
        default:
          return YarnVersion.Berry;
      }
    }
    throw new IllegalStateException("Unable to resolve current Yarn version: " + output);
  }
}
