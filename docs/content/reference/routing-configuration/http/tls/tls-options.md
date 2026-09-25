---
title: "Traefik TLS Options Documentation"
description: "Learn how to configure the transport layer security (TLS) connection in Traefik Proxy. Read the technical documentation."
---

The TLS options allow one to configure some parameters of the TLS connection.

!!! important "'default' TLS Option"

    The `default` option is special.
    When no tls options are specified in a tls router, the `default` option is used.  
    When specifying the `default` option explicitly, make sure not to specify provider namespace as the `default` option does not have one.  
    Conversely, for cross-provider references, for example, when referencing the file provider from a docker label,
    you must specify the provider namespace, for example:  
    `traefik.http.routers.myrouter.tls.options=myoptions@file`

!!! important "Providers"

    TLS options are not supported by label or tag-based providers. However, you can define them when using a [KV provider](../../other-providers/kv.md).

!!! important "TLSOption in Kubernetes"

    With the [TLSOption resource](../../kubernetes/crd/tls/tlsoption.md), the option named `default` applies to every router
    that does not reference a TLSOption explicitly, whatever the namespace it is defined in.
    The [`defaultTLSResourcesNamespace`](../../../install-configuration/providers/kubernetes/kubernetes-crd.md#defaulttlsresourcesnamespace) provider option
    restricts the namespace this cluster-wide default can be defined in.

### Server Name Association

The TLS options are configured on a router, but they are applied during the TLS handshake,
that is to say before the routing occurs, when the server name (SNI) is the only information available.
A TLS options reference is therefore always mapped to the host names found in the `Host` part of the router rule,
and neither to the router nor to its rule.
There could also be several `Host` parts in a rule, in which case the TLS options reference is mapped to as many host names.

In the case of domain fronting, if the TLS options associated with the Host header and the SNI are different,
Traefik responds with a `421 Misdirected Request` status code.

### Conflicting TLS Options

Since a TLS options reference is mapped to a host name, a conflict occurs when a configuration introduces a situation
where the same host name, on the same entry point, is matched with two different TLS options references,
such as in the example below:

```yaml tab="Structured (YAML)"
# Dynamic configuration

http:
  routers:
    routerfoo:
      rule: "Host(`example.com`) && Path(`/foo`)"
      tls:
        options: foo

    routerbar:
      rule: "Host(`example.com`) && Path(`/bar`)"
      tls:
        options: bar
```

```toml tab="Structured (TOML)"
# Dynamic configuration

[http.routers]
  [http.routers.routerfoo]
    rule = "Host(`example.com`) && Path(`/foo`)"
    [http.routers.routerfoo.tls]
      options = "foo"

  [http.routers.routerbar]
    rule = "Host(`example.com`) && Path(`/bar`)"
    [http.routers.routerbar.tls]
      options = "bar"
```

If that happens, both mappings are discarded, and the host name (`example.com` in this example)
gets associated with the `default` TLS options instead.

The conflict detection is not limited to a single provider:
routers coming from different providers, for example a router defined with a container label
and another one defined with the file provider, conflict with each other as soon as they serve
the same host name on the same entry point.

!!! important "Default TLS Options"

    The `default` TLS options are the fallback of the conflict resolution,
    and should therefore not be less secure than the options they can replace.
    A router relying on a mutual TLS authentication (`clientAuth`), for example,
    no longer enforces it if a conflict on its host name falls back to `default`
    TLS options that do not require it.

    The surest way to avoid this is to have all the routers serving the same host name,
    on the same entry point, reference the same TLS options.

#### Strict TLS Options

The [`core.strictTLSOptions`](../../../install-configuration/configuration-options.md#opt-core-stricttlsoptions)
install configuration option disables the fallback to the `default` TLS options.
When it is enabled, the routers involved in the conflict are marked in error and are not built at all,
and the host name is no longer mapped to any TLS options.

!!! warning "Disabled routers"

    Enabling `strictTLSOptions` fails closed: a conflict disables all the routers serving the conflicting host name
    on the concerned entry point, until the conflict is resolved.

```yaml tab="File (YAML)"
## Install configuration
core:
  strictTLSOptions: true
```

```toml tab="File (TOML)"
## Install configuration
[core]
  strictTLSOptions = true
```

```bash tab="CLI"
## Install configuration
--core.strictTLSOptions=true
```

### Minimum TLS Version

```yaml tab="Structured (YAML)"
# Dynamic configuration

tls:
  options:
    default:
      minVersion: VersionTLS12

    mintls13:
      minVersion: VersionTLS13
```

```toml tab="Structured (TOML)"
# Dynamic configuration

[tls.options]

  [tls.options.default]
    minVersion = "VersionTLS12"

  [tls.options.mintls13]
    minVersion = "VersionTLS13"
```

### Maximum TLS Version

We discourage the use of this setting to disable TLS1.3.

The recommended approach is to update the clients to support TLS1.3.

```yaml tab="Structured (YAML)"
# Dynamic configuration

tls:
  options:
    default:
      maxVersion: VersionTLS13

    maxtls12:
      maxVersion: VersionTLS12
```

```toml tab="Structured (TOML)"
# Dynamic configuration

[tls.options]

  [tls.options.default]
    maxVersion = "VersionTLS13"

  [tls.options.maxtls12]
    maxVersion = "VersionTLS12"
```

### Cipher Suites

See [cipherSuites](https://godoc.org/crypto/tls#pkg-constants) for more information.

```yaml tab="Structured (YAML)"
# Dynamic configuration

tls:
  options:
    default:
      cipherSuites:
        - TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
```

```toml tab="Structured (TOML)"
# Dynamic configuration

[tls.options]
  [tls.options.default]
    cipherSuites = [
      "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
    ]
```

!!! important "TLS 1.3"

    Cipher suites defined for TLS 1.2 and below cannot be used in TLS 1.3, and vice versa. (<https://tools.ietf.org/html/rfc8446>)  
    With TLS 1.3, the cipher suites are not configurable (all supported cipher suites are safe in this case).
    <https://golang.org/doc/go1.12#tls_1_3>

### Curve Preferences

This option allows setting the preferred elliptic curves.

The names of the curves defined by [`crypto`](https://godoc.org/crypto/tls#CurveID) (e.g. `CurveP521`) and the [RFC defined names](https://tools.ietf.org/html/rfc8446#section-4.2.7) (e. g. `secp521r1`) can be used.

See [CurveID](https://godoc.org/crypto/tls#CurveID) for more information.

```yaml tab="Structured (YAML)"
# Dynamic configuration

tls:
  options:
    default:
      curvePreferences:
        - CurveP521
        - CurveP384
```

```toml tab="Structured (TOML)"
# Dynamic configuration

[tls.options]
  [tls.options.default]
    curvePreferences = ["CurveP521", "CurveP384"]
```

### Strict SNI Checking

With strict SNI checking enabled, Traefik won't allow connections from clients that do not specify a server_name extension
or don't match any of the configured certificates.
The default certificate is irrelevant on that matter.

```yaml tab="Structured (YAML)"
# Dynamic configuration

tls:
  options:
    default:
      sniStrict: true
```

```toml tab="Structured (TOML)"
# Dynamic configuration

[tls.options]
  [tls.options.default]
    sniStrict = true
```

### ALPN Protocols

_Optional, Default="h2, http/1.1, acme-tls/1"_

This option allows specifying the list of supported application level protocols for the TLS handshake,
in order of preference.
If the client supports ALPN, the selected protocol will be one from this list, 
and the connection will fail if there is no mutually supported protocol.

```yaml tab="Structured (YAML)"
# Dynamic configuration

tls:
  options:
    default:
      alpnProtocols:
        - http/1.1
        - h2
```

```toml tab="Structured (TOML)"
# Dynamic configuration

[tls.options]
  [tls.options.default]
    alpnProtocols = ["http/1.1", "h2"]
```

### Client Authentication (mTLS)

Traefik supports mutual authentication, through the `clientAuth` section.

For authentication policies that require verification of the client certificate, the certificate authority for the certificates should be set in `clientAuth.caFiles`.

In Kubernetes environment, CA certificate can be set in `clientAuth.secretNames`. See [TLSOption resource](../../kubernetes/crd/tls/tlsoption.md) for more details.

The `clientAuth.clientAuthType` option governs the behaviour as follows:

| Option    |  Operation | 
| --------- | ----------- |
| <a id="opt-NoClientCert" href="#opt-NoClientCert" title="#opt-NoClientCert">`NoClientCert`</a> | Disregards any client certificate.| 
| <a id="opt-RequestClientCert" href="#opt-RequestClientCert" title="#opt-RequestClientCert">`RequestClientCert`</a> | Asks for a certificate but proceeds anyway if none is provided. |
| <a id="opt-RequireAnyClientCert" href="#opt-RequireAnyClientCert" title="#opt-RequireAnyClientCert">`RequireAnyClientCert`</a> | Requires a certificate but does not verify if it is signed by a CA listed in `clientAuth.caFiles` or in `clientAuth.secretNames`. |
| <a id="opt-VerifyClientCertIfGiven" href="#opt-VerifyClientCertIfGiven" title="#opt-VerifyClientCertIfGiven">`VerifyClientCertIfGiven`</a> | If a certificate is provided, verifies if it is signed by a CA listed in `clientAuth.caFiles` or in `clientAuth.secretNames`. Otherwise proceeds without any certificate. |
| <a id="opt-RequireAndVerifyClientCert" href="#opt-RequireAndVerifyClientCert" title="#opt-RequireAndVerifyClientCert">`RequireAndVerifyClientCert`</a> |  requires a certificate, which must be signed by a CA listed in `clientAuth.caFiles` or in `clientAuth.secretNames`. |
| <a id="opt-RequireAndVerifyClientCertWithCRLs" href="#opt-RequireAndVerifyClientCert" title="#opt-RequireAndVerifyClientCertWithCRLs">`RequireAndVerifyClientCertWithExpiry`</a> |  requires a certificate, which must be signed by a CA listed in `clientAuth.caFiles` or in `clientAuth.secretNames`.<br /> Provided certificate must be valid according to it's CRL spec. More about CRL handling [here](#expiry-check) |

```yaml tab="Structured (YAML)"
# Dynamic configuration

tls:
  options:
    default:
      clientAuth:
        # in PEM format. each file can contain multiple CAs.
        caFiles:
          - tests/clientca1.crt
          - tests/clientca2.crt
        clientAuthType: RequireAndVerifyClientCert
```

```toml tab="Structured (TOML)"
# Dynamic configuration

[tls.options]
  [tls.options.default]
    [tls.options.default.clientAuth]
      # in PEM format. each file can contain multiple CAs.
      caFiles = ["tests/clientca1.crt", "tests/clientca2.crt"]
      clientAuthType = "RequireAndVerifyClientCert"
```

#### Expiry Validation

Traefik supports CRL handling through the `clientAuth.expiry.crl` section.
There is multiple ways to load and handle CRLs.

!!! important "Performance impact"

  CRL validation is handled after client certificate validation and increase computational load on each request.
  You should be very carefull on wich routes will use this option as using it everywhere may increase latency significantly and/or lead to OOM issues.
  No matter how CRLs are loaded they will be loaded in Traefik memory, having very large CRL files and/or a large number of files may lead to significant memory usage increase.

This section of configuration requires `clientAuth.clientAuthType = "RequireAndVerifyClientCertWithExpiry"` to be effective.

| Option    |  Operation  |
| --------- | ----------- |
| <a id="opt-expiry-crl-mode" href="#opt-expiry-crlmode" title="#opt-expiry-crlmode">`clientAuth.expiry.crl.mode`</a> | Defines how Traefik will handle client certificate CRL validation.<br /> More info [here](crl-validation-behavior) |
| <a id="opt-expiry-crl-load" href="#opt-expiry-crl-load" title="#opt-expiry-crl-load">`clientAuth.expiry.crl.loadMode`</a> | Defines how Traefik will handle reference files loading.<br /> More info [here](crl-files-loading) |
| <a id="opt-expiry-crl-load-files-location" href="#opt-expiry-crl-load-files-location" title="#opt-expiry-crl-load-files-location">`clientAuth.expiry.crl.filesLocation`</a> | Defines from wich path Traefik will load CRL files when CRLs are loaded through `file` mode. Files must be valid CRL files.<br /> More info [here](crl-files-loading) |
| <a id="opt-expiry-crl-load-http-expiration" href="#opt-expiry-crl-load-http-expiration" title="#opt-expiry-crl-load-http-expiration">`clientAuth.expiry.crl.httpExpirationStrategy`</a> | Defines how Traefik will handle expired CRLs when they are loaded through `HTTP`.<br /> More info [here](crl-files-loading) |

##### CRL validation behavior

Traefik behavior validation behavior can be controled via `clientAuth.expiry.crl.mode`:

| Mode    |  Description                                                  |
| ------- | ------------------------------------------------------------- |
| noop    | No operation, will not check certificate sfor CRL attributes. |
| lax     | Will check certificates for CRL attribute and enforce when attribute is present. **Will not** enforce if a certificate has no CRL attribute. Traefik will check for each certificates in the verified chain if they are expired against their CRL file and apply this validation logic. |
| enforce | Will check certificates for CRL attribute, enforce when attribute is present, reject if attribute is not present. Traefik will check for each certificates in the verified chain if they are expired against their CRL file and apply this validation logic. |

##### CRL file loading

Traefik supports two CRL loading methods `file` and `HTTP`.

| Load Mode |  Description                        |
| --------  | ----------------------------------- |
| `file`      | This load mechanism relies on CRL files loaded through a file path accessible by traefik. This mean you are responsible to load CRL files in Traefik running environment and maintain them up to date. This mode does not check for **CRL Expiry** and trusts the provided files without checking their signature and expiry against the emitting CA.  |
| `HTTP`      | This load mechanism relies on loading CRL files through HTTP calls using the ditribution point provided by the verified client certificate. Traefik when loading a CRL this way will check CRL file signature and expiry date. CRL files are loaded on the fly with the first request made referencing the CRL file in certificate chain. |

When using `HTTP` loading, you need to select an expiration handling strategy.

| Crl Expiration Strategy    |  Description                                                  |
| -------------------------- | ------------------------------------------------------------- |
| `open`         | When a CRL file expires, Traefik will continue to serve HTTP routes whilst loading a new valid CRL file in the background. |
| `failedClosed` | When a CRL file expires, Traefik will, on the first request referencing this file, lock all requests until a new valid CRL file is loaded. This option ensures all requests uses a non expired client certificate but can momentarily **significantly** increase request latency and Traefik resource usage. If a CRL file download fails, Traefik will deny client request with a HTTP 401 and try to reload the file on the next request acquiring a lock. |


```yaml tab="Structured (YAML)"
# Dynamic configuration

tls:
  options:
    default:
      clientAuth:
        # in PEM format. each file can contain multiple CAs.
        caFiles:
          - tests/clientca1.crt
          - tests/clientca2.crt
        clientAuthType: RequireAndVerifyClientCert
        expiry:
          crl:
            mode: enforce
            providerwhitelist:
              - mycrlendpoint.crt
              - myothercrlendpoint.crt

```

```toml tab="Structured (TOML)"
# Dynamic configuration

[tls.options]
  [tls.options.default]
    [tls.options.default.clientAuth]
      # in PEM format. each file can contain multiple CAs.
      caFiles = ["tests/clientca1.crt", "tests/clientca2.crt"]
      clientAuthType = "RequireAndVerifyClientCert"
```

### Disable Session Tickets

_Optional, Default="false"_

When set to true, Traefik disables the use of session tickets, forcing every client to perform a full TLS handshake instead of resuming sessions.

```yaml tab="Structured (YAML)"
# routing configuration

tls:
  options:
    default:
      disableSessionTickets: true
```

```toml tab="Structured (TOML)"
# routing configuration

[tls.options]
  [tls.options.default]
    disableSessionTickets = true
```

```yaml tab="Kubernetes"
apiVersion: traefik.io/v1alpha1
kind: TLSOption
metadata:
  name: default
  namespace: default

spec:
  disableSessionTickets: true
```

{% include-markdown "includes/traefik-for-business-applications.md" %}
