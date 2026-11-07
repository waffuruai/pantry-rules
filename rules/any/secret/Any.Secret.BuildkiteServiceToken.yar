// betterleaks v1.10.0's buildkite-service-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_BuildkiteServiceToken
{
    meta:
        description     = "Detected a Buildkite agent, package, or portal token, which may expose CI/CD workloads or packages."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "BuildkiteServiceToken"
        severity        = "high"
        score           = 80
        id              = "buildkite-service-token"
        confidence      = "high"
        keyword         = "bkaa_"
        keyword         = "bkaj_"
        keyword         = "bkar_"
        keyword         = "bkct_"
        keyword         = "bkpt_"
        keyword         = "bkpat_"
        keyword         = "bkps_"
        skip_entropy_lt = "3.5"

    strings:
        $secret = /\b(bkaa_[A-Za-z0-9_-]{75}|bkaj_[A-Za-z0-9_-]{333}|bkar_[A-Za-z0-9_-]{73}|bkct_[A-Za-z0-9_-]{73}|bkpt_[A-Za-z0-9_-]{199}|bkpat_[A-Za-z0-9_-]{54}|bkps_[A-Za-z0-9_-]{64})(?:$|[^A-Za-z0-9_-])/  // gitleaks:allow

    condition:
        $secret
}
