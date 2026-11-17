// betterleaks v1.10.0's couchbase-capella-api-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_CouchbaseCapellaApiKey
{
    meta:
        description     = "Detected a Couchbase Capella API key secret, which may allow unauthorized access to Couchbase Capella management APIs."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "CouchbaseCapellaApiKey"
        severity        = "high"
        score           = 80
        id              = "couchbase-capella-api-key"
        confidence      = "high"
        keyword         = "couchbase"
        keyword         = "capella"
        skip_entropy_lt = "4.0"

    strings:
        $secret = /\b(?:[cC][oO][uU][cC][hH][bB][aA][sS][eE]|[cC][aA][pP][eE][lL][lL][aA])(?:.|[\n\r]){0,32}?(?:[aA][pP][iI](?:.|[\n\r]){0,12}?(?:[kK][eE][yY]|[sS][eE][cC][rR][eE][tT])|[kK][eE][yY](?:.|[\n\r]){0,12}?[sS][eE][cC][rR][eE][tT])(?:.|[\n\r]){0,32}?\b([a-zA-ZA-Za-z0-9+\/]{60,120}={0,2})\b/  // gitleaks:allow

    condition:
        $secret
}
