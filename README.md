# Veracode Auto Mitigate

## Description
Command line app that mitigates flaws in Veracode based on CWE, scan type, and specific text in the description.

## Parameters
`-mode`: [LogOnly|ProposeOnly|ProposeAndAccept] optional (overrides config file if provided)
`-config`: path to JSON config file

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
      "cweList": "80, 79",
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
 **_Configuration Notes_**:
 1. The `appsListTextFile` parameter should be used when `allApps` is set to `false`. It should be a text file with target app IDs on separate lines.
 2. The `cweList` parameter should be a comma separated list of CWEs to target for mitigation.
 3. The `requiredTextInDesc` parameter will search for text in the flaw description. The text to search for should be placed in the `requiredText` parameter as an array. For example, you can use this to target flaws on a specific cookie from a dynamic scan by including the cookie name. To use regular expression matching beginning and end with `/` making sure to double `\`.
 4. The `mitigationType` must be `comment`, `fp`, `appdesign`, `osenv`, or `netenv`.
 5. The `module` and `source` parameters cannot be set when `dynamic = true`. To use regular expression matching beginning and end with `/` making sure to double `\`.
## Credentials File
The credentials file should be set up as follows:
```
veracode_api_key_id = ID HERE
veracode_api_key_secret = SECRET HERE
```

## Executables
The executable is available in the release section of the repository: https://github.com/brian1917/vcodeAutoMitigate/releases

## Third-party Packages
github.com/brian1917/vcodeapi (https://godoc.org/github.com/brian1917/vcodeapi)
