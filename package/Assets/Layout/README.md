# Layout assets

Place captured layout assets here. See
[docs/Asset-Preparation.md](../../../docs/Asset-Preparation.md) (sections 2 and 3).

- `start2.bin` — default Start menu layout, Method A (seeded into the default profile by the engine)
- `StartPins.json` — Start pin list for Method B (`applyOnce: true`); a reference artifact only,
  assigned via **Intune Settings Catalog → Configure Start Pins**, *not* applied by the engine.
  Use Method A **or** B for a fleet, not both.
- `LayoutModification.xml` — default taskbar pins (user-changeable)

These are organization-specific and are not committed by default.
