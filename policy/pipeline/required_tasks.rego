package policy.pipeline.required_tasks

import future.keywords.in

import data.lib

# Note: I created the required_task_refs list by plucking out the testing
# related tasks from the build pipeline definitions in the build-definitions
# repo. Run `kustomize build pipelines/hacbs` in that repo to see the latest
# definitions.

# METADATA
# title: Pipeline does not include all required check tasks
# description: |-
#   Every build pipeline is expected to contain a set of checks and tests that
#   are required by the Enterprise Contract. This rule confirms that the pipeline
#   definition includes all the expected tasks.
#
#   The matching is done using the taskRef name rather than the pipeline task name.
#
# custom:
#   short_name: required_tasks
#   failure_msg: Required tasks %s were not found in the pipeline's task list
#   required_task_refs:
#   - clamav-scan
#   - conftest-clair
#   - get-clair-scan
#   - sanity-inspect-image
#   - sanity-label-check
#   - sast-go
#   - sast-java-sec-check
#
deny[result] {
	# Find the data in the annotations
	required_list := rego.metadata.rule().custom.required_task_refs

	# Convert it to a set
	required := {t | t := required_list[_]}

	# The set of tasks that we did find
	found := {t | t := input.spec.tasks[_].taskRef.name}

	# The set difference is the set of missing tasks
	missing := required - found

	# Trigger this rule if any are missing
	count(missing) != 0

	# Pass back the usual result map
	result := lib.result_helper(rego.metadata.chain(), [lib.quoted_values_string(missing)])
}

# METADATA
# title: Pipeline does not include the 'new-scanner' task
# description: |-
#   This is a dummy rule for demoing a rule with an effective date in the future.
#
#   Notice the effective date is Sep 1st.
#
# custom:
#   short_name: new_scanner
#   failure_msg: Required task %s was not found in the pipeline's task list
#   effective_on: 2022-09-01T00:00:00Z
#
deny[result] {
	found := {t | t := input.spec.tasks[_].taskRef.name}
	not "new-scanner" in found
	result := lib.result_helper(rego.metadata.chain(), ["new-scanner"])
}
