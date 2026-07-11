# Launch Checklist

Launch readiness requires accepted evidence for every launch-blocking gate in `gates.json`. Use this checklist as a human tracker, not as a second source of truth. This is a `checkedBy: human` gate record: the builder agent may link evidence, but only a named human distinct from the builder identity clears items.

- [ ] `G-OPERATOR-01`: independent operator run accepted.
- [ ] `G-TARGET-01`: production-equivalent Drupal target verified.
- [ ] `G-ROUTE-01` through `G-ROUTE-06`: route boundary, drift, repeated-item counts, target-required routes, and front-page behavior accepted.
- [ ] `G-BROWSER-01`, `G-BROWSER-02`, and `G-EDITOR-01`: public browser, first-fold brand, and non-admin editor evidence accepted.
- [ ] `G-PARITY-01`: applicable content, media, visual/design, functional, navigation, Views/page, form/integration, redirect, and SEO parity accepted.
- [ ] `G-CONTENT-01`, `G-CONTENT-02`, `G-COMPOSITION-01`, `G-COMPOSITION-02`, and `G-CANVAS-01`: Drupal ownership and editor-maintainability evidence accepted.
- [ ] `G-RECIPE-01` and `G-CONFIG-01`: installed substrate, bounded Recipe plan, and tracked config evidence accepted.
- [ ] `G-INTENT-01`, `G-FIELD-01`, `G-OFFROAD-01`, and `G-SEO-01`: intent, field output, rendered SEO, and off-road evidence accepted.
- [ ] `G-VERIFY-01`, `G-VERIFY-02`, and `G-BLIND-01`: independent, live-target, and blind adversarial review evidence accepted.
- [ ] `G-HANDOFF-01` and `G-MAINTAINER-01`: human decisions and named maintainer verdict accepted.
- [ ] `G-LAUNCH-01`: accessibility, performance, security/privacy, final QA, deployment, accepted exceptions, and rollback plan accepted.

Link accepted evidence beside each cleared item. If this checklist conflicts with `gates.json`, update the checklist from `gates.json` before making a launch claim.
