# Demo Licenses and Provenance

ContinuityForge ships only synthetic demonstration narratives. Demo licensing is separate from the MIT license for source code and repository documentation.

## License map

| Material | Location | Origin | License |
|---|---|---|---|
| Alpha/Beta continuity fixtures | `examples/alpha.txt`, `examples/beta.txt`, `examples/proposals.json` | Original ContinuityForge test narrative | MIT, with the repository |
| North Pier revision demo | `examples/north_pier/**` | Original ContinuityForge demo narrative | CC0-1.0 dedication; see [`LICENSES/NORTH_PIER_DEMO.md`](../LICENSES/NORTH_PIER_DEMO.md) |
| ContinuityForge code and documentation | repository excluding separately identified material | ContinuityForge contributors | MIT; see [`LICENSE`](../LICENSE) |

## North Pier provenance

The North Pier v1/v2 text, names, events, identifiers, expected impact cases, and supporting descriptions were created for this repository. They do not quote or adapt a novel, screenplay, game, chat log, customer record, or third-party dataset. Any resemblance to real people, places, or events is coincidental.

The demo is intentionally small and transparent. It exercises:

- one unchanged evidence span;
- one uniquely moved multiline span;
- one repeated span with ambiguous exact destinations;
- one old exact quote absent from the target (the fixture author changed it, but the engine does not infer a cause);
- claim-owned and operator-event-owned evidence descriptors.

The machine-readable case file is a demonstration expectation manifest, not a frozen import or CLI output schema.

## Reuse

The North Pier fixtures are dedicated under CC0-1.0 so tutorials, tests, screenshots, and compatible tools can reuse or modify them without an attribution requirement. A link to ContinuityForge is appreciated but optional. See the dedicated notice for the authoritative scope and license link.

## Adding demo material

Contributors adding a new fixture must:

1. provide original text or material with a license compatible with redistribution;
2. record origin and license here or in a dedicated file under `LICENSES/`;
3. avoid real secrets, personal data, production exports, and proprietary prompts;
4. avoid characters, passages, logos, and datasets whose reuse rights are unclear;
5. identify generated or adapted material and the terms that permit redistribution;
6. keep expected outputs separate from any schema claimed to be stable.
