# Hierarchical Access Control with Role Inheritance
package app.rbac.hierarchical

import rego.v1

reachable_roles := graph.reachable(data.static.roles_graph, input.roles)

user_permissions contains permission if {
	some role in reachable_roles
	some permission in data.static.permissions[role]
}


default allow := false

allow if input.action in user_permissions
