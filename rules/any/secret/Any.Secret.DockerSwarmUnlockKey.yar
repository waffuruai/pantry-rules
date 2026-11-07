// betterleaks v1.10.0's docker-swarm-unlock-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_DockerSwarmUnlockKey
{
    meta:
        description     = "Docker Swarm unlock key."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "DockerSwarmUnlockKey"
        severity        = "high"
        score           = 80
        id              = "docker-swarm-unlock-key"
        confidence      = "high"
        keyword         = "swmkey-1-"
        skip_entropy_lt = "3.5"

    strings:
        $secret = /\b(SWMKEY-1-[A-Za-z0-9+\/]{40,50})/  // gitleaks:allow

    condition:
        $secret
}
