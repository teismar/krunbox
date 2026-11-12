## Description
<!-- Provide a clear summary of the changes and motivation. -->

## Type of Change
- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to change)
- [ ] Documentation update
- [ ] Test addition / enhancement

## Checklist
- [ ] Code follows project style guidelines (Native GTK4/Libadwaita widgets, zero custom CSS overrides).
- [ ] All existing and new tests pass locally under `xvfb-run -a pytest -v tests/`.
- [ ] Desktop integration validated with `desktop-file-validate` and `appstreamcli validate --no-net`.
- [ ] Added test coverage for newly introduced functionality.
- [ ] Documentation updated to reflect changes where applicable.
