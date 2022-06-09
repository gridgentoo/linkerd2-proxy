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

## Admission controller

* Should only apply to HTTPRoute resources that bind to `Server`s. Other
  HTTPRoutes are ignored.
  * We should NOT support binding to `Namespace`, etc (at least initially); as
    this creates ambiguity, i.e. with `Gateway` resources.
  * Should we require that a label be set on these resources? To avoid
    conflicting admission controllers...

## Policy controller

* Watch HTTPRoute resources (by label? per above)
* Update server responses based on available routes
* Controller must provide routes to proxy in order of preference so that, when
  there are multiple equivalent route matches, the first matching route is used
  (i.e., with the preference order dictated by Gateway API spec).
* At least one route MUST be returned for all servers that may serve HTTP.
  * When no routes target a server, a default (empty) route should be returned
    with the labels `group='',kind='default',name=''`.
* For each returned route, authorizations should be returned:
  * Any AuthorizationPolicy instances that target the Server must be included
    for all routes on that server.
  * Additionally, any AuthorizationPolicy instances that target the HTTPRoute
    must be included only for that route.
  * If no AuthorizationPolicy instances apply to either the server or the route,
    the cluster's default authorization policy applies.

## Install

* How do Gateway API types get installed?
  * Optional?
    * Install takes a flag that indicates whether the API types are installed.
