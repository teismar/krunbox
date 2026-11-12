---
version: "0.1.2"
level: pair
processes:
  design: pair
  implementation: pair
  testing: pair
  documentation: pair
  review: pair
  deployment: pair
---

This format is based on [AI-DECLARATION.md](https://ai-declaration.md/en/0.1.2).

## Notes

- **Collaboration Model**: Pair programming between human maintainer (`teismar`) and Google DeepMind Antigravity AI assistant.
- **Human Understanding & Architecture**: The maintainer actively directs system design, understands the internal codebase and runtime boundaries (crun-krun microVM virtualization, KVM isolation, non-bypassable host firewall filtering, and native Libadwaita desktop integration), and inspects all implementations.
- **Testing & Verification**: Every component, CLI workflow, and GTK4 widget is tested and verified locally through 298 automated tests under virtual display (`xvfb-run -a pytest`) and standard desktop validation tools (`desktop-file-validate`, `appstreamcli validate`).
