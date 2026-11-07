// betterleaks v1.10.0's elastic-cloud-api-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_ElasticCloudApiKey
{
    meta:
        description     = "Identified an Elastic Cloud Serverless API key, which may expose Elasticsearch and Kibana resources to unauthorized access."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "ElasticCloudApiKey"
        severity        = "high"
        score           = 80
        id              = "elastic-cloud-api-key"
        confidence      = "high"
        keyword         = "essu_"
        skip_entropy_lt = "3.5"

    strings:
        $secret = /\b(essu_[A-Za-z0-9_\-]{60,200}={0,2})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
