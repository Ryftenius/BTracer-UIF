# SKUGGA SDK

[Developer guide](../Docs/DEVELOPMENT.md) — build, IPC integration, diagnostics, and release checks.

- Product: 1.0.1; SDK: 0.3; packet protocol: 3.
- [Packet ABI](include/skugga/skugga_ipc.h): SKUGGA_IPC_* records and SkuggaIpc* values.
- [VEH exports](include/skugga/skugga_veh.h): define IX_SKUGGA_IMPORTS and link SKUGGA.lib.
- [Reference host](samples/host/SkuggaSdkHost.cpp): owned-process local collection.

IPC-only consumers do not link SKUGGA.lib. Use matching headers and runtime.
