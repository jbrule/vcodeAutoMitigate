# Veracode Auto Mitigate

## Description
Command line app that mitigates flaws in Veracode based on CWE, scan type, and specific text in the description.

## Running
The application can be run on cmdline with Golang installed
```bash
export GOFLAGS=-buildvcs=false
go run ./veracode-automitigate-app/  -mode LogOnly -config my-mitigations.config
```

## Parameters
`-config`: path to JSON config file

`-mode`: [LogOnly|ProposeOnly|ProposeAndAccept] optional (overrides config file setting if provided)

## Configuration File
A sample config file is below:
```
{
    "auth": {
      "credsFile": "/Users/bpitta/.veracode/credentials"
    },
    "scope": {
        "allApps": false,
        "appListTextFile": "applist.txt",
        "regexAppNameExclude": "^Retired"
    },
    "mode":{
      "logOnly": true,
      "proposeOnly": false,
      "proposeAndAccept": false
    },
    "targetFlaws": {
      "cweList": "80,79",
      "requireTextInDesc": true,
      "requiredText":["textToSearchFor1","textToSearchFor2","/^MatchPrefixAnd\\d+/"],
      "module": "module name", # Optional -> This and dynamic = true are mutually exclusive.
      "source": "CustomerData.cs", # Optional -> This and dynamic = true are mutually exclusive.
      "static": true,
      "dynamic": false
    },
    "mitigationInfo":{
        "mitigationType": "netenv",
        "proposalComment": "Proposal text",
        "approvalComment": "Approval text"
    }
}
 ```
### Auth
- `auth.credsFile`: Path to file containing Veracode API credentials (cannot be used when proposerCredsFile or acceptorCredsFile are set)
- `auth.proposerCredsFile`: Path to file containing Veracode API credentials used for Mitigation Proposal. This account is also used to enumerate applications and flaws. (must be combined with acceptorCredsFile)
- `auth.acceptorCredsFile`: Path to file containing Veracode API credentials used for Mitigation Acceptance. (must be combined with proposerCredsFile)

The credentials file should be set up as follows:
```
veracode_api_key_id = ID HERE
veracode_api_key_secret = SECRET HERE
```

### Scope
 - `scope.allApps` (boolean) set to true to inspect all applications returned by the application API. (cannot be used when targetFlaws.cweList is set to "*")
 - `scope.appList` (CSV as string) parameter should be used when `allApps` is set to `false`. It should contain a comma delimited list of application IDs.
 - `scope.appsListTextFile` (file path as string) parameter should be used when `allApps` is set to `false`. It should be a text file with target app IDs on separate lines. NOTE: The `appList` setting supersedes this setting.
 - `scope.regexAppNameExclude` (Regex as string) filter out applications with name matching the provided regular expression. (Make sure to double `\`)
### Mode
 - `mode.logOnly` (boolean) Only log mitigation matches. Do not create mitigation proposals or approve mitigations.
 - `mode.proposeOnly` (boolean) Propose mitigations
 - `mode.proposeAndAccept` (boolean) Proposed and Approve mitigations
### TargetFlaws
 - `targetFlaws.cweList` (CSV as string) parameter should be a comma separated list of CWEs to target for mitigation. Can be set to "*" to mitigate all CWE types. (Cannot be used in combination with scope.allApps option. This is to avoid accidental misconfiguration)
 - `targetFlaws.severityList` (CSV as string) parameter should be a comma separated list of severity levels to target for mitigation. "*" is default. Should be used in combination with cweList "*" if wanting to mitigate all findings by severity level.

 Possible severity List Values
 |Value|Description|
 |-----|-----------|
 |0|Informational|
 |2|Low|
 |3|Medium|
 |4|High|
 |5|Very High|

 - `targetFlaws.requiredTextInDesc` parameter will search for text in the flaw description. The text to search for should be placed in the `requiredText` parameter as an array. For example, you can use this to target flaws on a specific cookie from a dynamic scan by including the cookie name. To use regular expression matching beginning and end with `/` making sure to double `\`.
 - `targetFlaws.requiredText` ([]string) Array of strings or regular expressions to match
 - `targetFlaws.static` (boolean) Inspect static scan result findings
 - `targetFlaws.dynamic` (boolean) Inspect dynamic scan result findings (cannot be combined with `module` and `source` parameters)
 - `targetFlaws.module` (string || ReGex as string) Module value to match. To use regular expression matching beginning and end with `/` making sure to double `\`. Cannot be set with `targetFlaws.dynamic = true`
 - `targetFlaws.source` (string || ReGex as string) Source value to match. To use regular expression matching beginning and end with `/` making sure to double `\`. Cannot be set with `targetFlaws.dynamic = true`
### MitigationInfo
 - `mitigationInfo.mitigationType` (string) must be `comment`, `fp`, `appdesign`, `osenv`, `acceptrisk`, or `netenv`.
 - `mitigationInfo.proposalComment` (string) Comment to provide with mitigation proposal
 - `mitigationInfo.approvalComment` (string) Comment to provide with mitigation approval

## Third-party Packages
github.com/brian1917/vcodeapi (https://godoc.org/github.com/brian1917/vcodeapi)
