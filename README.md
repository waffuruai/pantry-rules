# pantry-rules

YARA rules Waffuru writes from samples we analyse, for [Pantry](https://github.com/waffuruai/pantry)'s malware scan. Pantry doesn't fetch them yet: it uses [YARA Forge](https://github.com/YARAHQ/yara-forge)'s community rules, plus any `.yar` you add to its rules directory (`wpantry rules` prints it).

## Layout

```
rules/<os>/<category>/<Platform>.<Category>.<Family>.yar        the rule
rules/<os>/<category>/<Platform>.<Category>.<Family>.test.toml  its test cases
```

- `<os>`: `any`, `windows`, `linux` or `macos`: the system the rule's targets run on.
- `<category>`: the threat, as Pantry classifies it (`miner`, `downloader`, `clipper`, `infostealer`, …).

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

## License

[MIT](LICENSE).
