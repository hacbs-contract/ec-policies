package policy.release.reproducible_build

import data.lib

# METADATA
# title: Verify the build process is reproducible.
# description: |-
#   Verification is still a work in progress.
# custom:
#   short_name: reproducible_build
#   failure_msg: Build process is not reproducible
#   effective_on: 2023-01-01T00:00:00Z
#
deny[result] {
	att := lib.pipelinerun_attestations[_]
    not att.predicate.metadata.reproducible
	result := lib.result_helper(rego.metadata.chain(), [])
}
