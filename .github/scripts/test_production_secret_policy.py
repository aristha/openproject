import unittest

from production_secret_policy import validate


DOCKERFILE = """# check=skip=SecretsUsedInArgOrEnv

FROM scratch
ENV SECRET_KEY_BASE=OVERWRITE_ME
ENV OPENPROJECT_COLLABORATIVE__EDITING__HOCUSPOCUS__SECRET=
"""


class ProductionSecretPolicyTest(unittest.TestCase):
    def test_upstream_defaults(self):
        self.assertEqual([], validate(DOCKERFILE, "name: build\n"))

    def test_non_placeholder_secret_is_rejected_without_logging_value(self):
        value = "synthetic-private-value-for-test"
        errors = validate(DOCKERFILE.replace("OVERWRITE_ME", value), "")
        self.assertTrue(errors)
        self.assertNotIn(value, "\n".join(errors))

    def test_nonempty_hocuspocus_secret_is_rejected(self):
        self.assertTrue(validate(DOCKERFILE + "ENV OPENPROJECT_COLLABORATIVE__EDITING__HOCUSPOCUS__SECRET=test\n", ""))

    def test_new_secret_argument_is_rejected(self):
        self.assertTrue(validate(DOCKERFILE + "ARG AWS_SECRET_ACCESS_KEY\n", ""))

    def test_indented_lowercase_credential_declarations_are_rejected(self):
        self.assertTrue(validate(DOCKERFILE + "  arg api_key\n", ""))

    def test_multiline_and_legacy_env_forms_are_checked(self):
        self.assertTrue(validate(DOCKERFILE + "ENV SAFE=yes \\\n    API_TOKEN=test\n", ""))
        self.assertTrue(validate(DOCKERFILE + "ENV API_TOKEN test\n", ""))

    def test_broader_check_exception_is_rejected(self):
        self.assertTrue(validate(DOCKERFILE.replace("skip=SecretsUsedInArgOrEnv", "skip=all"), ""))

    def test_workflow_build_arguments_and_secrets_are_rejected(self):
        for key in ("build-args", "secrets", "secret-envs", "secret-files"):
            with self.subTest(key=key):
                self.assertTrue(validate(DOCKERFILE, f"    {key}: forbidden\n"))


if __name__ == "__main__":
    unittest.main()
