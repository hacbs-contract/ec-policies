# METADATA
# custom:
#   effective_on: 2022-01-01T00:00:00Z
package policy.pipeline.basic

import data.lib

expected_kind := "Pipeline"

# (Not sure if we need this, but I'm using it to test the docs build.)

# Fixme: It doesn't fail if the kind key is entirely missing..

# METADATA
# title: Check the kind is "Pipeline"
# description: |-
#   A sanity check to confirm the input data has the expected kind.
# custom:
#   short_name: unexpected_kind
#   failure_msg: Unexpected kind '%s'
#
deny[result] {
	expected_kind != input.kind
	result := lib.result_helper(rego.metadata.chain(), [input.kind])
}
