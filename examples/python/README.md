# Python C API examples

Purpose: demonstrate the C library and profile matching via Python, and a separate synthetic WSGI host integration of the Python request gate. Build the C library first; see the root README. The WSGI example can receive host-owned principal and operation-authorization hooks, but its default standalone run is unauthenticated and only for synthetic local demonstrations.
 The host may supply a trusted, fixed operation identifier at construction; submitted headers and signal values never select that operation. This example does not provide authentication or a production entrypoint.
