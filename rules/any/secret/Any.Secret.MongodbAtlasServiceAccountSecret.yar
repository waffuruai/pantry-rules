// betterleaks v1.10.0's mongodb-atlas-service-account-secret rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_MongodbAtlasServiceAccountSecret
{
    meta:
        description       = "Detected a MongoDB Atlas service account client secret, which could allow unauthorized Atlas administration API access when paired with a service account client ID."
        author            = "betterleaks"
        reference         = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license           = "MIT"
        os                = "any"
        category          = "secret"
        family            = "MongodbAtlasServiceAccountSecret"
        severity          = "high"
        score             = 80
        id                = "mongodb-atlas-service-account-secret"
        confidence        = "high"
        keyword           = "mdb_sa_sk_"
        component1        = "mongodb-atlas-service-account-id"
        skip_entropy_le   = "3.0"
        skip_regex_secret = "^mdb_sa_sk_[0-9]{40}$"  // gitleaks:allow

    strings:
        $secret = /\b(mdb_sa_sk_[A-Za-z0-9_-]{40})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
