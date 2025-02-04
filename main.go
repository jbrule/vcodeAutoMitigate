package main

import (
	"log"
	"io"
	"os"
	"strings"
	"time"
	"regexp"

	"github.com/brian1917/vcodeapi"
	//"github.com/davecgh/go-spew/spew"
)



func main() {
	// PARSE CONFIG FILE AND LOG CONFIG SETTINGS
	config := parseConfig()

	// SET UP LOGGING FILE
	errorLogfile, err := os.OpenFile(config.Name+"-error-"+time.Now().Format("20060102_150405")+".log", os.O_CREATE|os.O_WRONLY, 0644)
	debugLogfile, err := os.OpenFile(config.Name+"-debug-"+time.Now().Format("20060102_150405")+".log", os.O_CREATE|os.O_WRONLY, 0644)
	infoLogfile, err := os.OpenFile(config.Name+"-info-"+time.Now().Format("20060102_150405")+".log", os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}

	mw := io.MultiWriter(os.Stdout, infoLogfile)

	var (
		errorLog *log.Logger
		debugLog *log.Logger
		infoLog  *log.Logger
	)

	errorLog = log.New(errorLogfile, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile)
	debugLog = log.New(debugLogfile, "DEBUG: ", log.Ldate|log.Ltime|log.Lshortfile)
  infoLog = log.New(mw, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile)

	infoLog.Printf("Started running")

	// SET SOME VARIABLES
	var appSkip bool
	var flaws []vcodeapi.Flaw
	var recentBuild string
	var errorCheck error
	var flawList []string
	var buildsBack int
	var a vcodeapi.DetReport

	debugLog.Printf("[*] Config Settings: \n %+v \n", config)
	infoLog.Printf("[*] Config Settings: \n %+v \n", config)

	var regexAppNameExclude = regexp.MustCompile(config.Scope.RegexAppNameExclude)

	// GET APP LIST
	appList := getApps(config.Auth.ProposerCredsFile, config.Scope.AllApps, config.Scope.AppList, config.Scope.AppListTextFile)
	appCounter := 0

	// CYCLE THROUGH EACH APP
	for appID, appName := range appList {
		//ADJUST SOME VARIABLES
		flawList = []string{}
		appSkip = false
		appCounter++

		infoLog.Printf("Processing \"%v\" App ID %v (%v of %v)\n", appName, appID, appCounter, len(appList))
		debugLog.Printf("Processing \"%v\" App ID %v (%v of %v)\n", appName, appID, appCounter, len(appList))

		if len(config.Scope.RegexAppNameExclude) > 0 && len(regexAppNameExclude.FindStringIndex(appName)) > 0 {
			debugLog.Println("App Name Matched for Exclusion")
			appSkip = true
		}

		//GET THE BUILD LIST
		buildList, err := vcodeapi.ParseBuildList(config.Auth.ProposerCredsFile, appID)
		if err != nil {
			debugLog.Println(err)
			errorLog.Printf("Processing App ID %v (%v of %v)\n", appID, appCounter, len(appList))
			errorLog.Println(err)
			continue
		}

		// GET FOUR MOST RECENT BUILD IDS
		if len(buildList) == 0 {
			appSkip = true
			flaws = nil
			recentBuild = ""
		} else {
			//GET THE DETAILED RESULTS FOR MOST RECENT BUILD
			a, flaws, _, errorCheck = vcodeapi.ParseDetailedReport(config.Auth.ProposerCredsFile, buildList[len(buildList)-1].BuildID)
			
			//spew.Dump(a)
			//spew.Dump(errorCheck)
			recentBuild = buildList[len(buildList)-1].BuildID
			buildsBack = 1
			// spew.Dump(buildList)
			//IF THAT BUILD HAS AN ERROR, GET THE NEXT MOST RECENT (CONTINUE FOR 4 TOTAL BUILDS)
			for i := 1; i < 4; i++ {
				if len(buildList) > i && errorCheck != nil {
					a, flaws, _, errorCheck = vcodeapi.ParseDetailedReport(config.Auth.ProposerCredsFile, buildList[len(buildList)-(i+1)].BuildID)

					//spew.Dump(a)
					recentBuild = buildList[len(buildList)-(i+1)].BuildID
					buildsBack = i + 1
					debugLog.Println(buildsBack)
				}
			}
			
			// IF 4 MOST RECENT BUILDS HAVE ERRORS, THERE ARE NO RESULTS AVAILABLE
			if errorCheck != nil {
				debugLog.Println("some sort of error")
				appSkip = true
			}
		}

		//CHECK FLAWS AND
		if appSkip == false {
			infoLog.Println("App not skipped")
			debugLog.Println("App not skipped")
			for _, f := range flaws {
				// ONLY RUN ON NEW, OPEN, AND RE-OPENED FLAWS
				if f.RemediationStatus == "New" || f.RemediationStatus == "Open" || f.RemediationStatus == "Reopened" {

					debugLog.Printf("Flaw ID \"%v\" CWE \"%v\" Severity \"%v\"", f.Issueid, f.Cweid, f.Severity)

					// ONLY RUN IF CWE MATHCHES
					cweMatches := 0
					cweList := strings.Split(config.TargetFlaws.CWEList, ",")
					for _, cwe := range cweList {
						if cwe == f.Cweid || cwe == "*" {
							//debugLog.Printf("  CWE Match")
							cweMatches++
						}
					}

					severityMatches := 0
					severityList := strings.Split(config.TargetFlaws.SeverityList, ",")
					for _, severity := range severityList {
						if severity == f.Severity || severity == "*" {
							//debugLog.Printf("  Severity Match")
							severityMatches++
						}
					}

					debugLog.Printf("  Matches found %v CWE %v Severity", cweMatches, severityMatches)

					if cweMatches > 0 && severityMatches > 0 {
						debugLog.Println("  Matches CWE and Severity Requirement. Reviewing additional criteria")
						// CHECK DESCRIPTION TEXT
						if (config.TargetFlaws.RequireTextInDesc == true && containsStrings(f.Description, config.TargetFlaws.RequiredText)) || config.TargetFlaws.RequireTextInDesc == false {
							//CHECK SCAN TYPE
							debugLog.Printf("  Checking scan type. Type is \"%v\"",f.Module)
							if (config.TargetFlaws.Static == true && (f.Module != "dynamic_analysis" && f.Module != "manual_analysis")) ||
								(config.TargetFlaws.Dynamic == true && f.Module == "dynamic_analysis") {

								//debugLog.Printf("  Severity of this flaw finding: %v",f.Severity)

								// IF A MODULE NAME IS PROVIDED AND DOES NOT MATCH. SKIP TO NEXT INTERATION
								if (len(config.TargetFlaws.Module) != 0 && !containsString(f.Module, config.TargetFlaws.Module)) {
									debugLog.Printf("  Module \"%v\" does not match \"%v\". Skipping to next flaw",config.TargetFlaws.Module,f.Module)
									continue
								}
								// IF A SOURCE IS PROVIDED AND DOES NOT MATCH. SKIP TO NEXT INTERATION
								if (len(config.TargetFlaws.Source) != 0 && !containsString(f.Sourcefile, config.TargetFlaws.Source)) {
									debugLog.Printf("  Source \"%v\" does not match \"%v\". Skipping to next flaw",config.TargetFlaws.Source,f.Sourcefile)
									continue
								}

								// Build Array
								debugLog.Println("  Appended to flawList")

								flawList = append(flawList, f.Issueid)
							}
						}
					}
				}
			}

			// IF WE HAVE FLAWS MEETING CRITERIA, RUN UPDATE MITIGATION API
			if len(flawList) > 0 {
				if config.Mode.LogOnly == true {
					debugLog.Printf("[*]LOG MODE ONLY - App ID: %v (%v) Flaw ID(s) %v meet criteria\n", appID, appName, strings.Join(flawList, ","))
					infoLog.Printf("[*]LOG MODE ONLY - App ID: %v (%v) Flaw ID(s) %v meet criteria\n", appID, appName, strings.Join(flawList, ","))

					_ = recentBuild

				} else {

					// SET THE ACTIONS
					actions := [2]string{config.MitigationInfo.MitigationType, "accepted"}

					// FOR PROPOSE ONLY, CYCLE THROUGH ONCE
					limit := 1

					if config.Mode.ProposeOnly == true {
						limit = 0
					}
					// CHECK CONFIGURATIONS AND MITIGATE AND/OR LOG
					for i := 0; i <= limit; i++ {
						var comment string
						var credFilePath string

						if i == 0 {
							credFilePath = config.Auth.ProposerCredsFile
							comment = config.MitigationInfo.ProposalComment
						} else {
							credFilePath = config.Auth.AcceptorCredsFile
							comment = config.MitigationInfo.ApprovalComment
						}

						mitigationError := vcodeapi.ParseUpdateMitigation(credFilePath, recentBuild,
							actions[i], comment, strings.Join(flawList, ","))
						// IF WE HAVE AN ERROR, WE NEED TO TRY 2 BUILDS BACK FROM RESULTS BUILD
						// EXAMPLE = RESULTS IN BUILD 3 (MANUAL); DYNAMIC IS BUILD 2; STATIC IS BUILD 1 (BUILD WE NEED TO MITIGATE STATIC FLAW)
						for i := 0; i < 1; i++ {
							if mitigationError != nil {
								debugLog.Println("in here")
								mitigationError = vcodeapi.ParseUpdateMitigation(config.Auth.ProposerCredsFile, recentBuild,
									actions[i], config.MitigationInfo.ProposalComment, strings.Join(flawList, ","))
							}
						}
						// IF EXPIRE ERROR IS STILL NOT NULL, NOW WE LOG THE ERROR AND EXIT
						if mitigationError != nil {
							debugLog.Printf("Loop Index:%v",actions[i])
							debugLog.Printf("[!] Mitigation Error: %v", mitigationError)
							debugLog.Printf("[!] Could not "+actions[i]+" mitigation for Flaw IDs %v in App ID %v", flawList, appID)
							
							infoLog.Printf("[!] Could not "+actions[i]+" mitigation for Flaw IDs %v in App ID %v", flawList, appID)
							
							errorLog.Printf("[!] Mitigation Error: %v", mitigationError)
							errorLog.Printf("[!] Could not "+actions[i]+" mitigation for Flaw IDs %v in App ID %v", flawList, appID)
							continue
						}
						// LOG SUCCESSFUL PROPOSED MITIGATIONS
						debugLog.Printf("[*] MITIGATION ACTION COMPLETED - App ID %v: "+actions[i]+" Flaw IDs %v\n", appID, strings.Join(flawList, ","))
						infoLog.Printf("[*] MITIGATION ACTION COMPLETED - App ID %v: "+actions[i]+" Flaw IDs %v\n", appID, strings.Join(flawList, ","))
					}
				}
			}
		}

		debugLog.Printf("",a)
	}

	debugLog.Printf("Completed running")
	infoLog.Printf("Completed running")
	defer debugLogfile.Close()
	defer infoLogfile.Close()
	defer errorLogfile.Close()
}

func containsStrings(haystack string, needles []string) bool {

	for _, needle := range needles {
		if containsString(haystack, needle) {
			return true
		}
	}

	return false
}

func containsString(haystack string, needle string) bool {
	if strings.HasPrefix(needle,"/") && strings.HasSuffix(needle,"/") {
		needle = strings.TrimPrefix(needle,"/")
		needle = strings.TrimSuffix(needle,"/")
		matched, _ := regexp.MatchString(needle,haystack)
		if matched {
			return true
		}
	} else if strings.Contains(haystack,needle) {
		return true
	}

	return false
}