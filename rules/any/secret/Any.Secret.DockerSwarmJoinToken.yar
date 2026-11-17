// betterleaks v1.10.0's docker-swarm-join-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_DockerSwarmJoinToken
{
    meta:
        description     = "Docker Swarm join token."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "DockerSwarmJoinToken"
        severity        = "high"
        score           = 80
        id              = "docker-swarm-join-token"
        confidence      = "high"
        keyword         = "swmtkn-1-"
        skip_entropy_lt = "3.5"

    strings:
        $secret = /\b(SWMTKN-1-[a-z0-9]{50,60}-[a-z0-9]{24,30})/  // gitleaks:allow

    condition:
        $secret
}
