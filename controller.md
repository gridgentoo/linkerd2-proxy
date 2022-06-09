# controller TODO

```text
  ,----------,
  |  Server  |
  '-A------A-'
    |      |   ,-------------,
    |      `---|  HTTPRoute  |
    |          '-A-----------'
    |            |   ,-----------------------,
    |            `---|  AuthorizationPolicy  |
    |                '-----------------------'
    |
    |   ,-----------------------,
    `---|  AuthorizationPolicy  |
        '-----------------------'
```

## Injector

* Read probes and always include (HTTP) probe ports in the proxy's inbound port
  list. Probe ports should always be discovered and cached.
  <https://github.com/linkerd/linkerd2/issues/8638>

## Policy controller

* Watch all `HTTPRoute` resources in the cluster (by label? per above)
* Update server responses based on available routes
* Controller must provide routes to proxy in order of preference so that, when
  there are multiple equivalent route matches, the first matching route is used
  (i.e., with the preference order dictated by Gateway API spec).
* At least one route MUST be returned for all servers that may serve HTTP.
  * When no routes target a server, a default (empty) route should be returned
    with the labels `group='',kind='default',name=''`.
* For each returned route, authorizations should be returned:
  * Any `AuthorizationPolicy` instances that target the `Server` must be
    included for all routes on that server.
  * Additionally, any `AuthorizationPolicy` instances that target the HTTPRoute
    must be included only for that route.
  * If no `AuthorizationPolicy` instances apply to either the server or the
    route, the cluster's default authorization policy applies.
* Must update `status` on `HTTPRoute` resources, as described in gateway API spec.
* XXX How to handle routes that include unsupported filters/backends (i.e. if
  the admission controller was bypassed)?
  * Probably need to reflect in `HTTPRoute` status
  * Probably need to inject inject routes that fail requests.
* TODO Synthesize servers/routes/policies for probes when existing
  servers/routes/policies do not exist.

## Admission controller

* Only configured when gateway API support is enabled.
* Should only apply to HTTPRoute resources that bind to `Server`s. Other
  HTTPRoutes are ignored.
  * We should NOT support binding to `Namespace`, etc (at least initially); as
    this creates ambiguity, i.e. with `Gateway` resources.
  * Should we require that a label be set on these resources? To avoid
    conflicting admission controllers...
* Rejects resources that include unsupported filters.
* Rejects resources that include `backendRefs`.

## Install

* How do Gateway API types get installed?
  * Optional?
    * Chart takes a flag that indicates whether the API types are installed,
      enables route watches in policy controller.
    * CLI detects CRD presence during install/upgrade and sets flag accordingly.
