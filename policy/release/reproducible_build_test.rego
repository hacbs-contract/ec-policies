package policy.release.reproducible_build

import data.lib

mock_data(reproducible) = d {
	d := [{"predicate": {
		"buildType": lib.pipelinerun_att_build_type,
		"metadata": {"reproducible": reproducible},
	}}]
}

test_reproducible {
    lib.assert_empty(deny) with input.attestations as mock_data(true)
}

test_not_reproducible {
	lib.assert_equal(deny, {{
        "code": "reproducible_build",
        "effective_on": "2023-01-01T00:00:00Z",
        "msg": "Build process is not reproducible"
    }}) with input.attestations as mock_data(false)
}
