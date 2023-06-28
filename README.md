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

Include the library in your project:
```clojure
{:deps {monkey/oci-sign {:mvn/version ..latest..}}}
```

Then require the namespace, and invoke the `sign` function.
```clojure
(require '[monkey.oci.sign :as sign])

;; Configuration should be according to spec
(def config ...)
(def req {:url "https://some-oci-url"
          :method :get})
;; Generate the signature headers
(def headers (sign/sign config req))

;; Send the request, e.g. using http-kit
(require '[org.httpkit.client :as http])
(http/get (:url req) {:headers headers})
;; ...
```

The configuration should contain the `:tenancy-ocid`, `:user-ocid`, `:key-fingerprint`
and the `:private-key`.  The private key must be an `RSAPrivateKey` object.  You can
get it by reading it from a file and then parse it using [the buddy library](https://cljdoc.org/d/buddy/buddy-core/1.11.418/api/buddy.core.keys.pem).

The request must at least contain the `:url` and `:method` (as a keyword).  You can also
add the date but it's best to let the signer generate and format it.

## TODO

Still todo:

- Add functionality for handling requests with a body (like `PUT` or `POST`).
- Add decend CI scripting (probably using [CircleCI](https://circleci.com)).

## License

MIT license
by Monkey Projects 2023
