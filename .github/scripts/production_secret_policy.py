"""Keep the Dockerfile check exception limited to upstream public defaults."""

from pathlib import Path
import re
import shlex
import sys


DEFAULTS = {
    "SECRET_KEY_BASE": "OVERWRITE_ME",
    "OPENPROJECT_COLLABORATIVE__EDITING__HOCUSPOCUS__SECRET": "",
}
SENSITIVE = re.compile(r"SECRET|TOKEN|PASS(?:WORD)?|CREDENTIAL|PRIVATE_?KEY|ACCESS_?KEY|API_?KEY", re.I)


def validate(dockerfile, workflow):
    errors = []
    if dockerfile.splitlines()[0] != "# check=skip=SecretsUsedInArgOrEnv":
        errors.append("Only the SecretsUsedInArgOrEnv check exception is allowed")
    seen = []
    logical_lines = re.sub(r"\\\r?\n", " ", dockerfile)
    for instruction, arguments in re.findall(r"^[ \t]*(ARG|ENV)\s+(.+)$", logical_lines, re.M | re.I):
        tokens = shlex.split(arguments, comments=True)
        if instruction.upper() == "ENV" and "=" not in tokens[0]:
            pairs = [(tokens[0], " ".join(tokens[1:]))]
        else:
            pairs = [(token.partition("=")[0], token.partition("=")[2]) for token in tokens]
        for name, value in pairs:
            if not SENSITIVE.search(name):
                continue
            if instruction.upper() != "ENV" or name not in DEFAULTS or value != DEFAULTS[name]:
                errors.append(f"Disallowed credential-like {instruction.upper()} name/default: {name}")
            seen.append(name)
    if sorted(seen) != sorted(DEFAULTS):
        errors.append("Expected exactly the two upstream credential-like ENV defaults")
    if re.search(r"^\s*(build-args|secrets|secret-envs|secret-files)\s*:", workflow, re.M | re.I):
        errors.append("This image workflow must not pass build arguments or build secrets")
    return errors


if __name__ == "__main__":
    errors = validate(Path("docker/prod/Dockerfile").read_text(),
                      Path(".github/workflows/fork-ghcr-slim.yml").read_text())
    if errors:
        sys.exit("\n".join(errors))
    print("Production secret policy passed: public defaults only; no build arguments or build secrets.")
