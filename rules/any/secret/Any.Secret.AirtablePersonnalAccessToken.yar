// betterleaks v1.10.0's airtable-personnal-access-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_AirtablePersonnalAccessToken
{
    meta:
        description         = "Uncovered a possible Airtable Personal AccessToken, potentially compromising database access and leading to data leakage or alteration."
        author              = "betterleaks"
        reference           = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license             = "MIT"
        os                  = "any"
        category            = "secret"
        family              = "AirtablePersonnalAccessToken"
        severity            = "high"
        score               = 80
        id                  = "airtable-personnal-access-token"
        confidence          = "high"
        keyword             = "airtable"
        skip_entropy_lt     = "3.3"
        skip_token_ratio_ge = "2.5"

    strings:
        $secret = /\b(pat[A-Za-z0-9]{14}\.[a-f0-9]{64})\b/  // gitleaks:allow

    condition:
        $secret
}
