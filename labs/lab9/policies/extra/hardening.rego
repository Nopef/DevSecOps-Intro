package main

deny contains msg if {
	input.kind == "Deployment"
	pod := input.spec.template.spec
	not pod.securityContext.runAsNonRoot
	msg := "Pod must set spec.template.spec.securityContext.runAsNonRoot to true"
}

deny contains msg if {
	input.kind == "Deployment"
	container := input.spec.template.spec.containers[_]
	allow_priv := object.get(container.securityContext, "allowPrivilegeEscalation", true)
	allow_priv == true
	msg := sprintf("Container '%s' must set allowPrivilegeEscalation to false", [container.name])
}

drop_includes_all(drop) if {
	drop[_] == "ALL"
}

deny contains msg if {
	input.kind == "Deployment"
	container := input.spec.template.spec.containers[_]
	capabilities := object.get(container.securityContext, "capabilities", {})
	drop := object.get(capabilities, "drop", [])
	not drop_includes_all(drop)
	msg := sprintf("Container '%s' must drop ALL capabilities", [container.name])
}

deny contains msg if {
	input.kind == "Deployment"
	container := input.spec.template.spec.containers[_]
	not container.resources.limits.memory
	msg := sprintf("Container '%s' must set resources.limits.memory", [container.name])
}

deny contains msg if {
	input.kind == "Deployment"
	container := input.spec.template.spec.containers[_]
	contains(container.image, ":")
	not contains(container.image, "@sha256:")
	msg := sprintf("Container '%s' must pin image by digest (@sha256:), not tag", [container.name])
}
