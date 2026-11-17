// betterleaks v1.10.0's mongodb-atlas-service-account-id rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

private rule Any_Secret_MongodbAtlasServiceAccountId
{
    meta:
        description     = "Found a MongoDB Atlas service account client ID."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "MongodbAtlasServiceAccountId"
        severity        = "high"
        score           = 80
        id              = "mongodb-atlas-service-account-id"
        confidence      = "high"
        keyword         = "mdb_sa_id_"
        skip_entropy_le = "3.0"

    strings:
        $secret = /\b(mdb_sa_id_[a-f0-9]{24})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
