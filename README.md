# vhost-user-backend

## Design

This crate provides convenient abstractions for implementing `vhost-user` device server backends:

- A vhost-user backend trait (`VhostUserBackend`)
- A public API for the backend to interact with (`VhostUserDaemon`)
- An structure including virtio queue related elements (`Vring`)
- A worker for receiving queue events and forwarding them to the backend.

## Usage

Users of this create are expected to implement the `VhostUserBackend` trait and to initialize the execution context by instantiating `VhostUserDaemon` and calling to its `start` method.
