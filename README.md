# Monkey Projects OCI Signature Generator

Generates signatures for an HTTP request for [OCI](https://cloud.oracle.com).

## Why?

Why not use the provided Oracle SDK for Java?  Because I want a library
that is small and has as few dependencies as possible, so I can use it
in GraalVM projects.  More specifically, to use them in native images
for OCI [functions](https://fnproject.io).

## Design

I have written the code according to the [specs provided by Oracle](https://docs.oracle.com/en-us/iaas/Content/API/Concepts/signingrequests.htm#six).
These were however incomplete, so I also had to reverse engineer their Java
code somewhat.  But eventually that did the trick.

## How to use it?

[![Clojars Project](https://img.shields.io/clojars/v/com.monkeyprojects/oci-sign.svg)](https://clojars.org/com.monkeyprojects/oci-sign)
[![CircleCI](https://circleci.com/gh/monkey-projects/oci-sign.svg?style=svg)](https://app.circleci.com/pipelines/github/monkey-projects/oci-sign)

Include the library in your project:
```clojure
{:deps {com.monkeyprojects/oci-sign {:mvn/version ..latest..}}}
```

Then require the namespace, and invoke the `sign-headers` and `sign` functions.
The `sign-headers` takes a regular Ring request, and extracts the headers that
should be included in the signature.  Which headers depends on the kind of request.
It always includes the date, host and a generated value that combines the method
and the path.  For `PUT` and `POST`, it also includes a body hash, but there
are exceptions (see below).  You can also influence this by passing an additional
boolean `exclude-body?`, to forcibly exclude the body from the signature, even
if it is a `POST` or `PUT`.

The `sign-headers` returns a map that can then be passed to `sign`, which will
generate the actual signature using the configuration.  The configuration holds
a private key, but also values that are used to build a `keyId` header value.
These headers should then be included in your request to the OCI endpoint.

```clojure
(require '[monkey.oci.sign :as sign])

;; Configuration should be according to spec
(def config {:tenancy-ocid "..."
             :user-ocid "..."
	     :key-fingerprint "..."
	     :private-key some-pk})
(def req {:url "https://some-oci-url"
          :method :get})
;; Generate the signature headers
(def headers (sign/sign config (sign/sign-headers req)))

;; Send the request, e.g. using http-kit
(require '[org.httpkit.client :as http])
(http/get (:url req) {:headers headers})
;; Process the result...
```

The configuration should contain the `:tenancy-ocid`, `:user-ocid`, `:key-fingerprint`
and the `:private-key`.  The private key must be an `RSAPrivateKey` object.  You can
get it by reading it from a file and then parse it using [the buddy library](https://cljdoc.org/d/buddy/buddy-core/1.11.418/api/buddy.core.keys.pem).

The request must at least contain the `:url` and `:method` (as a keyword).  You can also
add the date but it's best to let the signer generate and format it.

## Martian

If you're using [Martian](https://github.com/oliyh/martian), you can include an interceptor
that is provided by this library to sign requests.  It takes the same configuration map
as the basic signing functions, with an extra option (`exclude-body?`, more on that below):

```clojure
(require '[monkey.oci.sign.martian :as mm])

;; Create Martian context that includes the signer interceptor
(def ctx (martian/bootstrap
          "http://api-host"
	  routes
	  {:interceptors (concat martian/default-interceptors
	                         [(mm/signer conf)
				  martian-http/perform-request])}))
;; Now send a request
(martian/response-for ctx :my-request {:key "value"})
;; The request will include authorization headers for OCI.
```

### Excluding The Body

Normally, for `PUT`, `POST` and `PATCH` requests, the body will also be included in the
signature calculation.  However, [some requests](https://docs.oracle.com/en-us/iaas/api/#/en/objectstorage/20160918/Object/PutObject)
require special treatment.  To allow for this, the signer accepts an additional
configuration property, `exclude-body?` which is a function that takes the request context
as argument and returns `true` if the body should be explicitly excluded, even though
it's a request with a body and one of the aforementioned HTTP methods.

## Copyright

Copyright (c) 2023 by Monkey Projects BV.
Licensed under [MIT](LICENSE)