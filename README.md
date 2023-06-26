# Monkey Projects OCI Signature Generator

Generates signatures for an HTTP request for [OCI](https://cloud.oracle.com).

## Why?

Why not use the provided Oracle SDK for Java?  Because I want a library
that is small and has as few dependencies as possible, so I can use it
in GraalVM projects.  More specifically, to use them in native images
for OCI [functions](https://fnproject.io).

## License

MIT license
by Monkey Projects 2023
