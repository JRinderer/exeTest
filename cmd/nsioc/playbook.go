package main

// Per-rule guidance used by "nsioc summarize": which stage of an attack a finding belongs to, how to tell
// whether it succeeded, and what to do next. Wording is deliberately conservative: the bundle can show that
// something was attempted or left behind, rarely that it worked.

const (
	phAttempt = "attempt"   // reconnaissance and attack attempts
	phExec    = "execution" // evidence that code ran or a payload is present
	phPersist = "persist"   // persistence and admin changes
	phTheft   = "theft"     // data and credential theft
	phContext = "context"   // exposure, crashes, cleanup, other context
)

var phaseTitle = map[string]string{
	phAttempt: "Reconnaissance and attack attempts",
	phExec:    "Execution and payload evidence",
	phPersist: "Persistence and admin changes",
	phTheft:   "Data and credential theft",
	phContext: "Exposure, cleanup and context",
}

var phaseOrder = []string{phExec, phPersist, phTheft, phAttempt, phContext}

type playbook struct {
	Phase   string
	Success string // how to tell whether it worked
	Next    string
}

// defaults per phase, used when a rule has no entry of its own
var phaseDefault = map[string]playbook{
	phAttempt: {phAttempt, "A log line proves an attempt, not success. Look for a dropped file, a new user, an outbound connection or a changed config at about the same time.", "Note source IPs and times; compare with the build install date."},
	phExec:    {phExec, "The artefact's presence is the evidence. Confirm in the live system that the file or process exists and when it was created.", "Preserve the file, hash it, check the HA peer, and do not reboot before evidence is captured."},
	phPersist: {phPersist, "Check who made the change and when (CLI audit log, older saved configs) and whether it was a planned admin change.", "Compare with a clean appliance of the same build; remove only after evidence is preserved."},
	phTheft:   {phTheft, "Look for a 200 response, or shell history showing the file was read or copied.", "Treat the data as exposed if success is likely: rotate keys, passwords and certificates."},
	phContext: {phContext, "Context only; it does not show an attack succeeded.", "Review in the full report."},
}

var playbooks = map[string]playbook{
	// --- attempts ---
	"log-pitboss-injection":   {phAttempt, "Look for the file the command tried to write (see file findings), outbound connections to the host named in the command, or a new user. Any of these suggests it ran. An attempt after the fix could not run, except 2 Oct onward on builds without the CVE-2026-88779 fix.", "Take the time of the line; check files and users from then; check firewall logs for the download host."},
	"log-pitboss-generic":     {phAttempt, "Same as log-pitboss-injection: execution is shown by a written file, an outbound connection or a new user, not by the log line.", "Check the matching files and users from that time."},
	"log-shell-injection":     {phAttempt, "This is the broadest rule and can match normal lines. Real attacks show a command such as curl, sh, wget or base64 after the metacharacter.", "Read the line; dismiss it if it is ordinary text."},
	"http-login-payload":      {phAttempt, "The request shows an attempt. Check the response status in the same line and the matching ns.log entry.", "Note the source IP and time."},
	"ua-base64-index":         {phAttempt, "The decoded command shows intent. It succeeded only if a later injected line picked it up and ran it: look for the files or connections it names.", "Read the decoded command and check for what it would create."},
	"ua-base64-php":           {phAttempt, "Webshell staging attempt. Check whether the target file exists (file findings, web folders) and later requests to it returning 200.", "Check the web folders for the file."},
	"ua-base64-whole":         {phAttempt, "An odd user agent; read the decoded text and judge.", "Read the decoded text."},
	"ua-base64-ktag":          {phAttempt, "Same as the other base64 user-agent payloads: intent is shown, success is not.", "Read the decoded text."},
	"log-exploit-strings":     {phAttempt, "Exploit strings in logs show an attempt. Check for the named file or process in the same period.", "Take the string and time; search the other findings for the same name."},
	"http-nsepa-probe":        {phAttempt, "A 1-byte request that checks whether the box is exploitable. It shows the box was found, nothing more.", "Note the source IPs."},
	"log-recon-marker":        {phAttempt, "Shows the box was probed. No success information.", "Note the source IPs."},
	"http-webshell-probe":     {phAttempt, "Read the HTTP status: 404 means the webshell was absent; 200 means it existed.", "If any status is 200, treat as COMPROMISE and look for the file."},
	"http-vpn-c-probe":        {phTheft, "Not a 200 here, so the config archive was absent or refused at that time.", "Check that no 200 exists in rotated logs."},
	"http-nsconmsg":           {phAttempt, "A web request to a CLI-only path suggests a webshell is being used. Check the status code and the source.", "Look for the webshell file."},
	"http-xsh-inventory":      {phAttempt, "Shows an attempt to fetch a payload. Check the status code.", "Note the source IPs."},
	"known-attacker-ip":       {phAttempt, "Contact from a published attacker IP. Look at the status codes: 200 on a sensitive path is a concern, 404/403 is not. A single line shows contact, not compromise.", "Check what that IP requested and whether any response was 200."},
	"known-attacker-domain":   {phAttempt, "The domain appears in a log. Its meaning depends on the context line: an outbound request from the appliance is the concerning case.", "Read the line to see whether the appliance called it."},
	"password-spray-range":    {phAttempt, "Failed logins from the range are an attempt; a success from it is the concern.", "Count failed versus successful logins from the range."},
	"scanner-ip":              {phAttempt, "A scanner-tagged address. Not an attack on its own.", "Do not block or conclude on this alone."},
	"dtls-crash":              {phAttempt, "A DTLS handshake failure together with a packet-engine crash close in time suggests a CVE-2026-88772 attempt. A crash alone proves nothing.", "Compare times of the crash and the handshake lines; check for core files."},
	"http-gateway-pkg-errors": {phAttempt, "Errors for package or icon files can be broken downloads or webshell staging. Check whether such a file exists.", "Check the Gateway folders."},

	// --- execution / payloads ---
	"known-malicious-hash":     {phExec, "A hash match is strong evidence the file is the published malicious sample.", "Preserve the file; check where it was and when."},
	"admin-persistence-script": {phExec, "One file that creates an admin, disables EPA and unbinds policies is an attacker script. Check the CLI audit log to see whether it was run.", "Check ns.log CMD_EXECUTED entries and the config for its effects."},
	"ps-payload":               {phExec, "A payload name in the process listing means it was running when the bundle was taken.", "Capture memory and the process tree before any restart."},
	"ps-decoy-name":            {phExec, "A decoy process name means an agent was running.", "Capture memory before any restart."},
	"sockstat-listener":        {phExec, "A listener on these ports means an implant was running.", "Capture memory and network state before any restart."},
	"setuid-sh":                {phExec, "A setuid shell is a privilege-escalation leftover and means code ran with high privilege.", "Preserve it and review recent commands."},
	"artefact-name":            {phExec, "Only the name appears in text, not the file. Check that the file exists in the bundle's file findings or on the appliance.", "Search for the file on the appliance."},
	"web-php-code":             {phExec, "PHP in a folder that should have none is a webshell.", "Preserve the file; check requests to it in the access log."},
	"conf-sec-monitor":         {phPersist, "The account exists in the config. Check the CLI audit log and older saved configs for when it was added and from where.", "Remove after evidence capture; rotate credentials."},

	// --- persistence / admin ---
	"conf-epa-no-auth":     {phPersist, "The setting is in the config, so EPA checks are effectively off. Compare older saved configs to date the change.", "Restore the EPA group; find who changed it."},
	"cli-epa-no-auth":      {phPersist, "The CLI log records the command. Check the user and Remote_ip: 127.0.0.1 means run from a shell on the appliance.", "Find the session that ran it."},
	"cli-user-epa-changes": {phPersist, "Normal admin work looks the same. Confirm each against change records; Remote_ip 127.0.0.1 is suspicious.", "Match each line to an admin and a change ticket."},
	"conf-system-user":     {phPersist, "Confirm each account is known. An unsaved addition is not in ns.conf.", "Compare with 'show system user' and older saved configs."},
	"cron-agent-pl":        {phPersist, "A cron entry starting a known implant means it was set to keep running.", "Preserve the entry and the files it names."},
	"cron-downloader":      {phPersist, "Some stock jobs download. Compare with a clean appliance.", "Compare with a clean build."},
	"nsafter-suspicious":   {phPersist, "nsafter.sh runs after every boot, so this survives a reboot.", "Preserve it before changing; check who edited it."},
	"startup-persistence":  {phPersist, "A decoder or one-liner in a startup file survives a reboot.", "Preserve before changing."},
	"httpd-webshell-alias": {phPersist, "The alias exposes a webshell; check the file it points to and requests to that URL returning 200.", "Find and preserve the target file."},
	"httpd-php-enabled":    {phPersist, "PHP enabled in the web server is how webshells run.", "Check which paths it covers."},
	"httpd-nonphp-as-php":  {phPersist, "Non-.php extensions run as PHP are how disguised webshells run.", "Check files with those extensions."},

	// --- theft ---
	"http-vpn-c-200":          {phTheft, "A 200 means the archive was served, so ns.conf and keys were likely downloaded. Confirm with the response size in the log line.", "Rotate keys, passwords and certificates."},
	"hist-key-theft":          {phTheft, "The command shows access to key or config files. If it was before the fix and not an admin, treat the secrets as exposed.", "Identify who ran it; rotate secrets if not authorised."},
	"hist-postexploit":        {phTheft, "Admins also use these tools. Confirm who ran them; ldapsearch against the bind account is the stolen-credential pattern.", "Match to an admin session; rotate the LDAP bind password if not authorised."},
	"file-config-staging":     {phTheft, "A copy of ns.conf or key files in a web or temp folder is a stolen config waiting to be fetched.", "Preserve it; treat secrets as exposed."},
	"cli-failed-nitro-login":  {phContext, "Shows the management interface is reachable from the internet and probed; it does not show a successful login.", "Restrict management access to admin networks."},
	"hist-platypus-bootstrap": {phExec, "A command that downloads the Platypus agent bootstrap means an agent was likely installed.", "Look for the agent files and processes."},
	"hist-kill-snmpd":         {phContext, "Killing customsnmpd can hide activity.", "Confirm who ran it."},
	"cron-wipe":               {phContext, "A job that deletes logs or files means evidence may be missing.", "Treat the logs as incomplete; obtain external logs."},

	// --- context ---
	"nsaaad-crash": {phContext, "Crashes of the authentication daemon fit the SAML crash attack but can have other causes. Relevant only if SAML is configured and the build lacks the CVE-2026-88779 fix.", "Collect the core files for Citrix Support."},
	"conf-build":   {phContext, "Shows whether the build is below the fix.", "Upgrade to the fixed build for your release."},
	"conf-saml":    {phContext, "SAML configured means CVE-2026-88779 applies.", "Upgrade to the SAML-fixed build."},
}

// playbookFor returns the entry for a rule, falling back to its phase default.
// Unknown rules (including file-* path rules) are placed by name.
func playbookFor(id string) playbook {
	if p, ok := playbooks[id]; ok {
		return p
	}
	switch {
	case hasPrefix(id, "file-core"), id == "monuploadd-wr", id == "vulnerable-monuploadd", id == "http-headless-chrome",
		id == "http-b64decode", id == "httperror-script-refs", id == "conf-epa-policy-unbind":
		return phaseDefault[phContext]
	case hasPrefix(id, "file-"), hasPrefix(id, "web-"), hasPrefix(id, "unit42-"), hasPrefix(id, "slap"), hasPrefix(id, "platypus-"):
		return phaseDefault[phExec]
	case hasPrefix(id, "httpd-"), hasPrefix(id, "cron-"), hasPrefix(id, "conf-"):
		return phaseDefault[phPersist]
	case hasPrefix(id, "hist-"):
		return phaseDefault[phTheft]
	}
	return phaseDefault[phAttempt]
}

func hasPrefix(s, p string) bool { return len(s) >= len(p) && s[:len(p)] == p }
