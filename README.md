# pantry-rules

YARA rules for [Pantry](https://github.com/waffuruai/pantry): malware rules Waffuru writes from samples we analyse, and secret rules translated from [betterleaks](https://github.com/betterleaks/betterleaks). Pantry doesn't fetch them yet: it uses [YARA Forge](https://github.com/YARAHQ/yara-forge)'s community rules, plus any `.yar` you add to its rules directory (`wpantry rules` prints it).

## Layout

```
rules/<os>/<category>/<Platform>.<Category>.<Family>.yar        the rule
rules/<os>/<category>/<Platform>.<Category>.<Family>.test.toml  its test cases
```

- `<os>`: `any`, `windows`, `linux` or `macos`: the system the rule's targets run on.
- `<category>`: the threat, as Pantry classifies it (`miner`, `downloader`, `clipper`, `infostealer`, …).

## Secret rules

`rules/any/secret/` holds one rule per betterleaks v1.10.0 rule (466), plus its global prefilter and filter. Its [README](rules/any/secret/README.md) catalogues them: what each finds, and a sample secret. They're generated: `mise run gen` translates `vendor/betterleaks/betterleaks.toml` with `tools/betterleaks.py`, and `mise run test` fails when the files differ from a fresh translation.

- **The regex:** each rule's regex is `$secret`.
- **Meta:** what YARA can't say goes in meta: keywords, entropy and token-ratio limits, skip lists, components, confidence. `tools/betterleaks.py`'s docstring lists every key.
- **Built-in filters:** five filters are programs, not lists. Each is a named built-in in Pantry, with betterleaks' source in a comment above the rule.
- **Live checks:** betterleaks can check a secret with its provider; these rules leave that out ([pantry#190](https://github.com/waffuruai/pantry/issues/190)).
- **Test cases:** each rule's `.test.toml` cases are sampled from its regex and confirmed by the pinned betterleaks. The secret is stored reversed so the file doesn't trip its own rule.
  - 397 of the 422 reportable rules have cases.
  - The other 25 need text the sampler can't produce, such as a path, a multi-line document or a checksum.
- **Our own filters:** `Any.Secret.PantryFilter.yar` is written by hand.

To change a secret rule, change the translator or add a rule of our own beside them; to take a newer betterleaks, replace `vendor/betterleaks/`, bump `VERSION` and the pin in `mise.toml`, and run `mise run gen`.

## Writing a rule

- Use YARA-X's strict dialect: an unescaped `{` in a regex or an unknown escape is an error, and `base64` strings are at least three characters.
- Give it `os`, `category`, `family`, `severity`, `score`, `author` and `reference` meta, and a `description` of what it catches.
- Add a `.test.toml` beside it: each `[[case]]` has a `text` and the `rules` it must match exactly (`[]` for text it must not match). Include at least one ordinary file it must not match.
- `wpantry rules gen SAMPLE…` drafts a rule from samples.

To try a rule with Pantry, copy it into the rules directory and scan:

```bash
cp rules/any/miner/Any.Miner.C3poolKit.yar "$(wpantry rules --json | jq -r .directory)/"
wpantry scan --path ~/Downloads --no-machine
```

## Development

`mise bootstrap`, then `mise run test`. `mise run gen` regenerates the secret rules.

## License

[MIT](LICENSE). The secret rules come from betterleaks (MIT): see [NOTICE](NOTICE).
