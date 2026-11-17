// betterleaks v1.10.0's azure-servicebus-connection-string rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_AzureServicebusConnectionString
{
    meta:
        description     = "Detected an Azure Service Bus or Event Hub shared access connection string."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "AzureServicebusConnectionString"
        severity        = "high"
        score           = 80
        id              = "azure-servicebus-connection-string"
        confidence      = "high"
        keyword         = "endpoint=sb://"
        keyword         = "sharedaccesskey"
        skip_entropy_le = "3.0"

    strings:
        $secret = /([Ee][nN][dD][pP][oO][iI][nN][tT]=[sS][bB]:\/\/[A-Za-z0-9-]+\.[sS][eE][rR][vV][iI][cC][eE][bB][uU][sS]\.[wW][iI][nN][dD][oO][wW][sS]\.[nN][eE][tT]\/;[Ss][hH][aA][rR][eE][dD][Aa][cC][cC][eE][sS][sS][Kk][eE][yY][Nn][aA][mM][eE]=[^;=\s'"]{1,128};[Ss][hH][aA][rR][eE][dD][Aa][cC][cC][eE][sS][sS][Kk][eE][yY]=[a-zA-ZA-Za-z0-9+\/]{32,100}={0,2}(?:;[Ee][nN][tT][iI][tT][yY][Pp][aA][tT][hH]=[^;\s'"]{1,128})?)/  // gitleaks:allow

    condition:
        $secret
}
