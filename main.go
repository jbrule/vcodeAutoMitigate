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

	mw := io.MultiWriter(os.Stdout, debugLogfile)

	var (
		errorLog *log.Logger
		debugLog *log.Logger
		infoLog  *log.Logger
	)

	errorLog = log.New(errorLogfile, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile)
	debugLog = log.New(mw, "DEBUG: ", log.Ldate|log.Ltime|log.Lshortfile)
  infoLog = log.New(infoLogfile, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile)

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
	appList := getApps(config.Auth.CredsFile, config.Scope.AllApps, config.Scope.AppList, config.Scope.AppListTextFile)
	appCounter := 0

	// CYCLE THROUGH EACH APP
	for _, appID := range appList {
		//ADJUST SOME VARIABLES
		var appName string
		flawList = []string{}
		appSkip = false
		appCounter++

		debugLog.Printf("Processing App ID %v (%v of %v)\n", appID, appCounter, len(appList))

		//GET THE BUILD LIST
		buildList, err := vcodeapi.ParseBuildList(config.Auth.CredsFile, appID)
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
			a, flaws, _, errorCheck = vcodeapi.ParseDetailedReport(config.Auth.CredsFile, buildList[len(buildList)-1].BuildID)
			
			appName = a.AppName

			//spew.Dump(a)
			//spew.Dump(errorCheck)
			recentBuild = buildList[len(buildList)-1].BuildID
			buildsBack = 1
			// spew.Dump(buildList)
			//IF THAT BUILD HAS AN ERROR, GET THE NEXT MOST RECENT (CONTINUE FOR 4 TOTAL BUILDS)
			for i := 1; i < 4; i++ {
				if len(buildList) > i && errorCheck != nil {
					a, flaws, _, errorCheck = vcodeapi.ParseDetailedReport(config.Auth.CredsFile, buildList[len(buildList)-(i+1)].BuildID)

					appName = a.AppName

					//spew.Dump(a)
					recentBuild = buildList[len(buildList)-(i+1)].BuildID
					buildsBack = i + 1
					debugLog.Println(buildsBack)
				}
			}

			if len(config.Scope.RegexAppNameExclude) > 0 && len(regexAppNameExclude.FindStringIndex(a.AppName)) > 0 {
				debugLog.Println("App Name Matched for Exclusion")
				appSkip = true
			}
			
			// IF 4 MOST RECENT BUILDS HAVE ERRORS, THERE ARE NO RESULTS AVAILABLE
			if errorCheck != nil {
				debugLog.Println("some sort of error")
				appSkip = true
			}
		}

		//CHECK FLAWS AND
		if appSkip == false {
			debugLog.Println("App not skipped")
			for _, f := range flaws {
				// ONLY RUN ON NEW, OPEN, AND RE-OPENE FLAWS
				if f.RemediationStatus == "New" || f.RemediationStatus == "Open" || f.RemediationStatus == "Reopened" {
					// ONLY RUN IF CWE MATHCHES
					matches := 0
					cweList := strings.Split(config.TargetFlaws.CWEList, ",")
					for _, cwe := range cweList {
						if cwe == f.Cweid {
							debugLog.Println("match")
							matches++
						}
					}
					debugLog.Printf("%v Matches found", matches)
					if matches > 0 {
						// CHECK DESCRIPTION TEXT
						if (config.TargetFlaws.RequireTextInDesc == true && containsStrings(f.Description, config.TargetFlaws.RequiredText)) || config.TargetFlaws.RequireTextInDesc == false {
							//CHECK SCAN TYPE
							debugLog.Println("checking scan type")
							if (config.TargetFlaws.Static == true && (f.Module != "dynamic_analysis" && f.Module != "manual_analysis")) ||
								(config.TargetFlaws.Dynamic == true && f.Module == "dynamic_analysis") {
								// Build Array
								debugLog.Println("Appended to flawList")

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
						if i == 0 {
							comment = config.MitigationInfo.ProposalComment
						} else {
							comment = config.MitigationInfo.ApprovalComment
						}
						mitigationError := vcodeapi.ParseUpdateMitigation(config.Auth.CredsFile, recentBuild,
							actions[i], comment, strings.Join(flawList, ","))
						// IF WE HAVE AN ERROR, WE NEED TO TRY 2 BUILDS BACK FROM RESULTS BUILD
						// EXAMPLE = RESULTS IN BUILD 3 (MANUAL); DYNAMIC IS BUILD 2; STATIC IS BUILD 1 (BUILD WE NEED TO MITIGATE STATIC FLAW)
						for i := 0; i < 1; i++ {
							if mitigationError != nil {
								debugLog.Println("in here")
								mitigationError = vcodeapi.ParseUpdateMitigation(config.Auth.CredsFile, recentBuild,
									actions[i], config.MitigationInfo.ProposalComment, strings.Join(flawList, ","))

							}
						}
						// IF EXPIRE ERROR IS STILL NOT NULL, NOW WE LOG THE ERROR AND EXIT
						if mitigationError != nil {
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
}

func containsStrings(haystack string, needles []string) bool {

	for _, needle := range needles {
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
	}

	return false
}