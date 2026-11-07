// betterleaks v1.10.0's clojars-api-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_ClojarsApiToken
{
    meta:
        description     = "Uncovered a possible Clojars API token, risking unauthorized access to Clojure libraries and potential code manipulation."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "ClojarsApiToken"
        severity        = "high"
        score           = 80
        id              = "clojars-api-token"
        confidence      = "high"
        keyword         = "clojars_"
        skip_entropy_le = "2.0"

    strings:
        $secret = /[Cc][Ll][Oo][Jj][Aa][Rr][Ss]_[A-Za-z0-9]{60}/  // gitleaks:allow

    condition:
        $secret
}
