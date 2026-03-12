#!/usr/bin/python3
#
# DanAmodio
#
# Profiles web enabled services 
#

from __future__ import print_function
import sys
import traceback
import argparse
import base64
import xml.etree.ElementTree as ET
#from HTMLParser import HTMLParser
from html.parser import HTMLParser
import httplib2
import socket
#import thread
import threading
import queue
import time
import ssl, OpenSSL
from urllib.parse import urlparse, urljoin
import json
import re

#reload(sys)  
#sys.setdefaultencoding('utf8')

if sys.version_info[0] >= 3:
    unicode = str

# GLOBALS
args = None
#threadLock = threading.Lock()
threads = []
exitFlag = False
qlock = threading.Lock()
qhosts = queue.Queue()

# --- Signature -> operator hints (single-GET followups) ---
HINTS = {
    "GitLab": [
        "Try: /users/sign_in, /explore, /help, /-/health, /-/metrics (if exposed)",
        "Enumerate: public projects, groups, exposed runners; look for CI/CD variables/secrets in logs/artifacts",
        "Check: instance version banner in HTML, and any open registration settings"
    ],
    "GitHub Enterprise": [
        "Try: /login, /session, /setup, /site/terms, /stafftools (auth-gated but good to know)",
        "Enumerate: public repos/orgs; look for exposed actions runners / packages endpoints"
    ],
    "Bitbucket": [
        "Try: /login, /j_atl_security_check, /rest/api/ (auth-gated but reveals stack sometimes)",
        "Enumerate: project keys, repo listing if anonymous access is enabled"
    ],
    "Azure DevOps Server": [
        "Try: /_signin, /_sso, /_apis/ (may reveal org/project surface)",
        "Look for: build artifacts exposure, feed endpoints, test result endpoints"
    ],
    "JFrog Artifactory": [
        "Try: /artifactory/, /ui/, /api/system/ping, /api/system/version (often auth-gated but quick indicators)",
        "Enumerate: anonymous repositories, misconfigured virtual repos, exposed build info"
    ],
    "Nexus Repository Manager": [
        "Try: /#welcome, #browse/browse, /service/rest/v1/status, /service/rest/swagger.json (if exposed)",
        "Enumerate: anonymous browse/download, blob store leaks via misconfig"
    ],
    "Harbor Registry": [
        "Try: /api/v2.0/, /c/login, /api/v2.0/systeminfo (sometimes partially exposed)",
        "Enumerate: public projects/repos, robot accounts, weak auth settings"
    ],
    "SonarQube": [
        "Try: /api/server/version, /api/system/status, /api/users/search (auth varies)",
        "Enumerate: public projects, issues, SCM leak paths; look for tokens in settings/config"
    ],
    "Rundeck": [
        "Try: /user/login, /api/ (auth varies), check if project listings leak",
        "High-value: job definitions often contain creds, scripts, or node inventory"
    ],
    "Apache Airflow": [
        "Try: /airflow/login, /api/v1/ (newer), /admin/ (older)",
        "High-value: connections/variables, DAG code, log endpoints, misconfigured auth"
    ],
    "Grafana": [
        "Try: /login, /api/health, /api/search (auth varies)",
        "High-value: data sources, dashboards with secrets/URLs, anonymous access"
    ],
    "Kibana": [
        "Try: /app/kibana, /api/status",
        "High-value: saved objects, index patterns; check if Elasticsearch is reachable too"
    ],
    "Splunk": [
        "Try: /en-US/account/login, /services/server/info (auth varies)",
        "High-value: deployment server, HEC endpoints, exposed apps/configs"
    ],
    "Prometheus": [
        "Try: /graph, /targets, /api/v1/status/buildinfo",
        "High-value: scrape targets reveal internal hosts; config may leak via misconfig"
    ],
    "Alertmanager": [
        "Try: /#/alerts, /api/v2/status",
        "High-value: receivers/webhooks reveal internal endpoints/tokens"
    ],
    "pgAdmin": [
        "Try: /login, check for default pgAdmin landing",
        "High-value: stored DB connections if compromised; check weak auth / exposed instance"
    ],
    "phpPgAdmin": [
        "Try: /, look for server listing / DB browser",
        "High-value: direct DB access surface; check default creds (where appropriate) and misconfig"
    ],
    "Cockpit": [
        "Try: /cockpit/, /cockpit/login",
        "High-value: host admin surface; check exposure + auth method"
    ],
    "Webmin": [
        "Try: /session_login.cgi",
        "High-value: historical vulns; confirm version and exposure scope"
    ],
    "Portainer": [
        "Try: /, /api/status, /api/endpoints (auth varies)",
        "High-value: Docker/K8s control plane; check unauth or weak auth"
    ],
    "Rancher": [
        "Try: /v3-public/, /dashboard/",
        "High-value: cluster creds, downstream kubeconfigs, API tokens"
    ],
    "Argo CD": [
        "Try: /api/v1/session, /api/version",
        "High-value: repo creds, cluster creds, app manifests; check SSO config"
    ],
    "Keycloak": [
        "Try: /realms/<realm>/.well-known/openid-configuration",
        "High-value: realm discovery, clients, misconfigured redirect URIs, admin console exposure"
    ],
    "Azure App Service": [
        "ARRAffinity cookie suggests App Service; consider: app service SCM/Kudu if discoverable",
        "Look for: *.scm.<host> patterns (don’t request here, just hint operators)"
    ],
    "AWS (Elastic Beanstalk / ALB hint)": [
        "x-amzn-trace-id suggests AWS; consider CloudFront/ALB in front; origin discovery may be needed",
        "Look for: default EB markers, and check if app leaks instance metadata links in HTML"
    ],
    "GCP (App Engine / trace hint)": [
        "x-cloud-trace-context suggests GCP; consider IAP/proxy layers and service-to-service endpoints",
        "Look for: default app engine markers or backend service names in HTML/JS"
    ],
    "Python or Django Debug Pages": [
        "Review pages for info leak or credentials in settings"
    ],
    "Gitea": [
        "Try: /users/sign_in, /explore, /explore/repos",
        "Enumerate: public projects, groups, exposed runners; look for CI/CD variables/secrets in logs/artifacts",
        "Check /-/admin/actions/runners, <your_gitea.com>/<org>/settings/actions/runners, <your_gitea.com>/<owner>/<repo>/settings/actions/runners"
    ],
    "phpinfo() Page": [
        "High-value info disclosure: reveals PHP version, modules, paths, env vars",
        "Look for: document root paths, temp dirs, upload dirs, loaded extensions",
        "Check: disable_functions, open_basedir, session.save_path",
        "Pivot: use module list to identify exploit paths (imagick, gd, ldap, etc)"
    ],
    "MCP Redirect": [
        "Redirect Location contains /mcp, /sse, or /messages (possible MCP server exposure)",
        "Followups: request the redirected endpoint directly and look for JSON-RPC (\"jsonrpc\":\"2.0\") or SSE (text/event-stream)",
        "Assess auth: if the MCP endpoint is open, inventory exposed tools/resources and any internal network reach"
    ],
    "MCP Server (Model Context Protocol)": [
        "Likely Model Context Protocol server exposed (tool-bridge for LLM clients)",
        "Followups: check for a dedicated MCP endpoint path (commonly /mcp) and whether auth is required",
        "Look for references to inspector tokens (e.g., MCP_PROXY_AUTH_TOKEN) or public docs that reveal endpoint paths"
    ],
    "MCP JSON-RPC Surface": [
        "JSON-RPC markers suggest an MCP-style API surface (often returns JSON-RPC error on wrong method/route)",
        "Followups: confirm the MCP endpoint path (often /mcp) and use a proper MCP client/inspector to list tools/resources",
        "Assess auth: bearer tokens, reverse proxy auth, or no auth (high risk if tools expose internal systems)"
    ],
    "MCP Endpoint Mentioned": [
        "Page references an MCP endpoint path (commonly /mcp per spec)",
        "Followups: try the referenced path directly and observe status codes, content-type, and redirects",
        "If present, validate whether it’s restricted to internal networks or protected by auth"
    ],
    "MCP SSE Surface": [
        "SSE markers suggest MCP-over-SSE style transport (often /sse + /messages pattern)",
        "Followups: identify the SSE endpoint and the paired POST messages endpoint; check for auth requirements",
        "If SSE is open, confirm whether it leaks endpoint/session info in events"
    ],
    "MCP Common Paths Referenced": [
        "Common MCP paths referenced in page content (/mcp, /sse, /messages)",
        "Followups: probe those paths (operator-driven) for JSON-RPC or SSE responses and auth challenges",
        "If exposed, inventory which backends/tools it can reach (highest-risk part of MCP exposure)"
    ],
    "SSO Redirect (Okta)": [
        "Redirect to Okta detected (.okta.com or /oauth2/default)",
        "Followups: identify auth server, check OIDC discovery endpoint, inspect client_id in redirect",
        "Look for redirect_uri validation weaknesses and exposed app IDs"
    ],
    "SSO Redirect (Entra ID)": [
        "Redirect to Microsoft login.microsoftonline.com detected",
        "Followups: extract tenant ID from redirect URL",
        "Check for legacy auth endpoints and user enumeration behavior"
    ],
    "SSO Redirect (Auth0)": [
        "Redirect to Auth0 tenant detected (*.auth0.com)",
        "Followups: identify tenant name, check /.well-known/openid-configuration",
        "Inspect redirect_uri and client_id parameters"
    ],
    "SSO Redirect (Ping)": [
        "Redirect to Ping Identity endpoint detected (/as/authorization.oauth2)",
        "Followups: inspect federation metadata endpoints and relay state handling",
        "Assess redirect URI validation"
    ],
    "SSO Redirect (Keycloak)": [
        "Redirect to Keycloak realm detected (/realms/)",
        "Followups: identify realm name and check /.well-known/openid-configuration",
        "Look for exposed admin console or misconfigured clients"
    ],
    "Jupyter Notebook": [
        "Try: /tree, /lab, /api/sessions, /api/kernels, /terminals",
        "Check: if token auth is enabled or the notebook loads directly",
        "Look for: credentials in notebook cells, mounted datasets, cloud keys in environment variables"
    ],

    "JupyterLab": [
        "Try: /lab, /lab/workspaces, /api/kernels, /api/sessions",
        "Check: if terminal access is enabled via /terminals",
        "Enumerate: running notebooks and inspect Python cells for secrets or dataset paths"
    ],

    "MLflow": [
        "Try: /mlflow, /api/2.0/mlflow/experiments/list, /api/2.0/mlflow/runs/search",
        "Enumerate: experiments, runs, model artifacts, and storage locations",
        "Look for: S3/GCS paths, training parameters, embedded secrets in experiment metadata"
    ],

    "Kubeflow": [
        "Try: _/pipeline, /pipeline, /pipeline/apis, _/jupyter, /notebook, /katib, _/tensorboards",
        "Enumerate: pipelines, runs, and notebooks accessible in the dashboard",
        "Look for: container images, service accounts, and pipeline parameters"
    ],

    "Kubeflow Pipelines": [
        "Try: /pipeline/apis/v1beta1/pipelines, /pipeline/apis/v1beta1/runs",
        "Enumerate: pipeline definitions and container execution steps",
        "Check: if pipelines can be triggered without authentication"
    ],

    "Prefect": [
        "Try: /flows, /flow_runs, /api/graphql",
        "Enumerate: workflow definitions and execution logs",
        "Look for: secrets used in ML training pipelines"
    ],

    "Dagster": [
        "Try: /graphql, /runs, /assets",
        "Enumerate: pipeline definitions and job runs",
        "Look for: container images or scripts executed by workflows"
    ],

    "TensorFlow Serving": [
        "Try: /v1/models, /v1/models/<model>",
        "Enumerate: available models and version status",
        "Check: if inference endpoints are accessible without authentication"
    ],

    "TorchServe": [
        "Try: /models, /predictions/<model>, /metrics",
        "Enumerate: registered models and inference endpoints",
        "Check: if model management APIs allow uploads or modifications"
    ],

    "Ray Dashboard": [
        "Try: /dashboard, /api/jobs, /api/actors",
        "Enumerate: running jobs, cluster nodes, and task history",
        "Check: if job submission APIs allow remote execution"
    ],

    "Weaviate": [
        "Try: /v1/schema, /v1/objects, /v1/graphql",
        "Enumerate: collections and stored vector objects",
        "Look for: embedded documents or knowledge base content"
    ],

    "Qdrant": [
        "Try: /collections, /collections/<name>, /points",
        "Enumerate: stored embedding collections",
        "Look for: documents used for RAG systems"
    ],

    "Milvus": [
        "Try: /collections, /entities, /metrics",
        "Enumerate: vector collections and stored embeddings",
        "Look for: indexed internal knowledge bases"
    ],

    "LangChain": [
        "Try: /chat, /api/chat, /api/agent, /docs",
        "Enumerate: LLM endpoints and tool integrations",
        "Look for: retrieval pipelines, API keys, or internal connectors"
    ],

    "LlamaIndex": [
        "Try: /query, /chat, /api/query",
        "Enumerate: document retrieval endpoints",
        "Look for: indexed documents used in RAG pipelines"
    ],

    "Label Studio": [
        "Try: /projects, /tasks, /data",
        "Enumerate: labeled datasets and annotation tasks",
        "Look for: training data or sensitive documents"
    ],

    "CVAT": [
        "Try: /tasks, /projects, /api",
        "Enumerate: labeling tasks and dataset images",
        "Look for: proprietary image datasets"
    ],

    "Superset": [
        "Try: /superset/welcome, /dashboard, /explore",
        "Enumerate: dashboards and data sources",
        "Look for: SQL queries revealing database structures"
    ],

    "Metabase": [
        "Try: /api/session/properties, /dashboard, /question",
        "Enumerate: dashboards and connected databases",
        "Look for: exposed queries and warehouse connections"
    ],

    "Redash": [
        "Try: /queries, /api/queries, /data_sources",
        "Enumerate: saved SQL queries and dashboards",
        "Look for: credentials or database schema details"
    ],

    "Roboflow Inference Server": [
        "Try: /docs, /openapi.json, /build, /notebook/start",
        "Enumerate: inference routes (/infer, /predict) and any model listing endpoints; verify if auth is required",
        "Check: if the bundled notebook environment is reachable; notebook access can lead to code execution and credential discovery"
    ],

}

def warn(*objs):
    print("[*][WARNING]: ", *objs, file=sys.stderr)

def error(*objs):
    print("[!][ERROR]: ", *objs)

def debug(*objs):
    if args.debug:
        #print("[*] DEBUG: ", *objs, file=sys.stderr)
        print("[*][DEBUG]: ", *objs)

def getHttpLib():
    h = httplib2.Http(".cache", disable_ssl_certificate_validation=True, timeout=5)
    # We handle redirects manually so we can print 30x Location hops.
    try:
        h.follow_redirects = False
    except Exception:
        pass
    return h
    
# HTML parser to read title tag
class TitleParser(HTMLParser):
    def __init__(self):
        self.tag = [None]
        self.title = None
        HTMLParser.__init__(self)
        
    def handle_starttag(self, tag, attrs):
        self.tag.append(tag)

    def handle_endtag(self, tag):
        self.tag.pop()

    def handle_data(self, data):
        tag = self.tag[-1] # peek at tag context
        if tag == "title":
            self.title = data

# TODO -- could go into body and grep entire response. also javascript. have some other ideas for this.
class LinkParser(HTMLParser):
    def __init__(self):
        self.links = []
        HTMLParser.__init__(self)
        
    def handle_starttag(self, tag, attrs):
        if tag=="a":
            for attr in attrs:
                if attr[0] == 'href':
                    self.links.append( attr[1] )
                    #print( "Found link: ", attr[1])

# Probing class
class Probe (threading.Thread):
    def __init__(self):
        self.url = None 
        self.resp = None
        self.respdata = None
        self.didFind = False
        self._hints_printed = set()
        self._mcp_redirect_tagged = False
        self._sso_redirect_tagged = set()
        
    def out(self, data):
        if args.output == "default":
            print( "[{status}][{length}] {url} | {data}".format(status=str(self.resp.status), length=str(len(self.respdata)), url=self.url, data=data) )
        elif args.output == "json":
            print( json.dumps({
                'status' : self.resp.status, 
                'length': len(self.respdata), 
                'url' : self.url, 
                'data': data
            }))
        elif args.output == "csv":
            print( "{status}, {length}, {url}, {data}".format(status=str(self.resp.status), length=str(len(self.respdata)), url=self.url, data=data) )
        elif args.output == "xml":
            print( "<item><status>{status}</status><length>{length}</length><url>{url}</url><data>{data}</data></item>".format(status=str(self.resp.status), length=str(len(self.respdata)), url=self.url, data=data) )

        if args.outputjson:
            args.outputjson.write( json.dumps( { 
                '_type' : 'found',
                'status' : self.resp.status, 
                'length': len(self.respdata), 
                'url' : self.url, 
                'data': data
            } ))

        sys.stdout.flush()

    def inBody(self, test):
        return True if self.respdata.find(test.encode())>-1 else False

    def inUrl(self, test):
        return True if self.resp.get('content-location','').find(test)>-1 else False

    def inHeader(self, header,test):
        if self.resp.get(header,'').find(test)>-1:
            return True
        return False

    def inMeta(self, test):
        try:
            if not self.respdata:
                return False

            html = self.respdata.decode(errors="ignore").lower()

            return True if test.lower() in html and "<meta" in html else False

        except:
            return False

    def inTitle(self, test):
        try:
            if not self.respdata:
                return False

            html = self.respdata.decode(errors="ignore")
            p = TitleParser()
            p.feed(html)

            if not p.title:
                return False

            return True if p.title.lower().find(test.lower()) > -1 else False
        except Exception:
            return False


    def found(self, signature):
        self.didFind = True
        self.out(signature)

        # Print operator hints (once per signature per host)
        hints = HINTS.get(signature)
        if not hints:
            return
        if signature in self._hints_printed:
            return
        self._hints_printed.add(signature)
        for h in hints:
            self.out("  HINT: " + h)
        
        # Print hints (once per signature per host)
        hints = HINTS.get(signature)
        if not hints:
            return

        if signature in self._hints_printed:
            return
        self._hints_printed.add(signature)

        for h in hints:
            self.out("  HINT: " + h)

    # https://en.wikipedia.org/wiki/%3F:#Python
    def evalRules(s):
        s.found("Wordpress") if s.inBody("wp-content/") or s.inBody("wp-includes") else 0
        s.found("WordPress") if s.inMeta("wordpress") else 0
        s.found("Drupal") if s.inBody("drupal.min.js") or s.inBody("Drupal.settings") or s.inBody("http://drupal.org") else 0 
        s.found("Coldfusion") if s.inBody(".cfm") or s.inBody(".cfc") else 0
        s.found("Coldfusion 11") if s.inBody("1997 - 2014 Adobe Systems Incorporated and its licensors") else 0
        s.found("Coldfusion Cookie") if s.inHeader("set-cookie", "CFTOKEN=") or s.inHeader("set-cookie", "CFAUTHORIZATION") else 0
        s.found("Accellion SFT") if s.inBody("Secured by Accellion") else 0
        s.found("F5 BIG-IP") if (s.inBody("licensed from F5 Networks") and s.inUrl("my.policy")) or (s.inBody("BIG-IP logout page") and s.inUrl("my.logout.php")) else 0
        s.found("Confluence") if s.inBody("login to Confluence") or s.inBody("Log in to Confluence") or s.inBody("com-atlassian-confluence") else 0
        s.found("JIRA") if s.inBody("JIRA administrators") or s.inBody("Jira Service Management") or s.inBody("jira.webresources") else 0
        s.found("Lotus Domino") if s.inBody("homepage.nsf/homePage.gif?OpenImageResource") or (s.inBody("Notes Client") and s.inBody("Lotus")) else 0
        s.found("Citrix ShareFile Storage Server") if s.inBody("ShareFile Storage Server") else 0
        s.found("IIS7 Welcome Page") if s.inBody("welcome.png") and s.inBody("IIS7") else 0
        s.found("IIS8 Welcome Page") if s.inBody("Microsoft Internet Information Services 8.0") and s.inBody("ws8-brand.png") else 0
        s.found("Citrix") if s.inBody("Citrix Systems") and s.inBody("vpn/") else 0
        s.found("Citrix") if s.inBody("/Citrix/SecureGateway") else 0
        s.found("Outlook Web App") if s.inBody("Outlook Web App") else 0
        s.found("MobileIron") if s.inBody("MobileIron") else 0
        s.found("VMware Horizon") if s.inBody("VMware Horizon") and s.inBody("connect to your desktop and applications") else 0
        s.found("Cisco VPN") if s.inBody("/+CSCOE+/logon.html") or s.inBody("SSL VPN Service") else 0
        s.found("Windows SBS") if s.inBody("Welcome to Windows Small Business Server") else 0
        s.found("Mediawiki") if s.inBody("wiki/Main_Page") or s.inBody("wiki/Special:") or s.inBody("wiki/File:") or s.inBody("poweredby_mediawiki") else 0
        s.found("Thycotic Secret Server") if s.inBody("Thycotic Secret Server") else 0
        s.found("Directory Listing") if s.inBody("Index of") or s.inBody("Parent Directory") else 0
        s.found("Junos Pulse") if s.inBody("dana-na") else 0
        s.found("Default Tomcat Homepage") if s.inBody("this is the default Tomcat home page") else 0
        s.found("Default Tomcat Homepage") if s.inBody("If you're seeing this, you've successfully installed Tomcat. Congratulations!") else 0 #tomcat7/8
        s.found("Default Tomcat Homepage w/ links to Tomcat Manager") if s.inBody("/manager/html") and s.inBody("/manager/status") else 0
        s.found("Quest Password Manager") if s.inBody("Quest Password Manager") else 0
        s.found("FogBugz") if s.inBody("FogBugz") and s.inBody("fogbugz.stackexchange.com") else 0
        s.found("WebSphere 6.1") if s.inBody("IBM HTTP Server") and s.inBody("infocenter/wasinfo/v6r1") else 0
        s.found("Default Glassfish Homepage") if s.inBody("GlassFish Server") and s.inBody("Your server is now running") else 0
        s.found("MobileGuard") if s.inBody("MobileGuard Compliance Home Page") else 0
        s.found("SAP Business Objects") if s.inUrl("BOE/BI") and s.inBody("servletBridgeIframe") else 0 # http://www.cvedetails.com/vulnerability-list/vendor_id-797/product_id-20077/SAP-Businessobjects.html
        s.found("SAP NetWeaver Application Server") if s.inHeader("server", "SAP NetWeaver Application Server") else 0
        s.found("Kentico") if s.inBody("CMSPages/GetResource.ashx") else 0
        s.found("vSphere") if s.inBody("client/VMware-viclient.exe") else 0
        s.found("ESXi") if s.inBody('content="VMware ESXi') else 0
        s.found("Juniper Web Device Manager") if s.inBody("Log In - Juniper Web Device Manager") else 0
        s.found("SNARE") if s.inBody("Intersect Alliance") and s.inBody("SNARE for") else 0
        s.found("HP System Management Homepage") if s.inBody("HP System Management Homepage") else 0
        s.found("Symantec Reporting") if s.inBody("log on to Symantec Reporting") else 0
        s.found("Silver Peak Appliance Management") if s.inBody("Silver Peak Systems") else 0
        s.found("EMC Unisphere") if s.inBody('src="engMessage.js"') and s.inBody("oemMessage.js") else 0
        s.found("Cisco Applications") if s.inBody("Installed Applications") and s.inBody("ciscologo.gif") else 0
        s.found("Cisco Prime Data Center Manager") if s.inBody("Cisco Prime") and s.inBody("Data Center Network Manager") else 0
        s.found("Axis Camera") if s.inBody("/view/index.shtml") else 0
        s.found("Apache Default") if s.inBody("This is the default web page for this server.") or s.inBody("Seeing this instead of the website you expected?") else 0
        s.found("Dell Remote Access Controller") if s.inBody("Dell Remote Access Controller") else 0
        s.found("Infoblox") if s.inBody('content="Infoblox WebUI Login Page') else 0
        s.found("Puppet Enterprise Console") if s.inBody("Puppet Enterprise Console") else 0
        s.found("Entrust") if s.inBody('content="Entrust SSM') else 0
        s.found("Under Construction") if s.inBody("does not currently have a default page") and s.inBody("Under Construction") else 0
        s.found("Barracuda Web Filter") if s.inBody("Barracuda Networks") and s.inBody("Web Filter") else 0
        s.found("Tripwire") if s.inBody("console/app.showApp.cmd") and s.inBody("Tripwire") else 0
        s.found("SolarWinds Orion") if s.inBody("SolarWinds Orion") or s.inBody("orionmaster.js.i18n.ashx") else 0
        s.found("Cisco ASDM") if s.inBody("Cisco ASDM") and s.inBody("startup.jnlp") else 0
        s.found("Red Hat Satellite") if s.inBody("Red Hat Satellite") and s.inBody("rhn-base.css") else 0
        s.found("DELL On Board Remote Management") if s.inBody("On Board Remote Management") and s.inBody("status.html") else 0
        s.found("Lansweeper") if s.inBody("Lansweeper") and s.inBody("lansweeper.js.aspx") else 0
        s.found("Raritan Dominion KX II (KVM)") if s.inBody("Raritan") and s.inBody("Dominion KX II") else 0
        s.found("HP iLO") if s.inBody("Hewlett-Packard") and s.inBody("iLO") else 0
        s.found("ArcSight Management Center") if s.inBody("<title>ArcSight Management Center</title>") else 0
        s.found("IIS Windows Server 8.5") if s.inBody("<title>IIS Windows Server</title>") and s.inBody("iis-85.png") else 0
        s.found("PowerEdge R420 iDRAC") if s.inBody("PowerEdge R420") and s.inBody("idrac") else 0
        s.found("Dell PowerVault TL4000 Tape Library") if s.inBody("<title>Dell PowerVault TL4000 Tape Library</title>") and s.inBody("RMULogin") else 0
        s.found("Codian ISDN") if s.inBody("<title>Codian ISDN") else 0
        s.found("BIG-IP Configuration Utility") if s.inBody("BIG-IP") and s.inBody("Configuration Utility") else 0
        s.found("iDRAC 8") if s.inBody("iDRAC8 - Login</title>") else 0
        s.found("Cisco Secure ACS") if s.inBody("<title>Cisco Secure ACS Login</title>") else 0
        s.found("Cisco Integrated Management Controller") if s.inBody("<title>Cisco Integrated Management Controller Login</title>") else 0
        s.found("Snap Server") if s.inUrl("/sadmin/GetLogin.event") else 0
        s.found("Palo Alto GlobalProtect Portal") if s.inBody("GlobalProtect Portal") else 0
        s.found("Demandware") if s.inBody("demandware.edgesuite") else 0
        s.found("McAfee Agent Activity Log") if s.inBody("AgentGUID") and s.inBody("Log") else 0
        s.found("Rails") if s.inBody("assets/javascripts") or s.inBody("assets/stylesheets") else 0
        s.found("Sharepoint") if s.inHeader("MicrosoftSharePointTeamServices", ".") or s.inHeader("microsoftsharepointteamservices", ".") else 0
        s.found("Sharepoint") if s.inHeader("X-SharePointHealthScore", ".") or s.inHeader("x-sharepointhealthscore", ".") else 0   
        s.found("Default JMX-Console") if s.inBody("/jmx-console") and s.inBody("Welcome to JBoss") else 0
        s.found("Axis2") if s.inBody("Login to Axis2 :: Administration page") or s.inBody("Welcome to the Axis2 administration console") else 0
        s.found("Ektron CMS400") if s.inBody("EktronClientManager") or  s.inBody("/WorkArea/FrameworkUI/js/ektron.javascript.ashx") or s.inBody("/WorkArea/FrameworkUI/js/Ektron/Ektron.Class.js") else 0
        s.found("Ektron CMS400 Login") if s.inBody("CMS400 Login") else 0
        s.found("Umbraco CMS") if s.inBody("/umbraco/") or s.inBody("Login - Umbraco") else 0
        s.found("PHPMyAdmin") if s.inBody("phpMyAdmin") and s.inBody("www.phpmyadmin.net") else 0
        s.found("Nagios") if s.inBody("Nagios Core") else 0
        s.found("Oracle Middleware") if s.inBody("Welcome to Oracle Fusion Middleware") else 0
        s.found("Oracle Reports") if s.inBody("Oracle Reports Services - Servlet") else 0
        s.found("Oracle Application Server") if s.inHeader("server", "Oracle-Application-Server") else 0
        s.found("Oracle Fusion Middleware") if s.inHeader("server", "Oracle-Web-Cache") else 0
        s.found("Oracle Integrated Lights Out Manager") if s.inHeader("server", "Oracle-ILOM-Web-Server") else 0
        s.found("Oracle iPlanet Web Server") if s.inHeader("server", "Oracle-iPlanet-Web-Server") else 0
        s.found("Oracle HTTP Server") if s.inHeader("server", "Oracle-HTTP-Server") else 0
        s.found("Oracle Apex") if s.inBody("Oracle APEX - Sign In") or s.inBody("Oracle APEX") or s.inBody("APEX_SUCCESS_MESSAGE") else 0
        s.found("Oracle Forms and Reports") if s.inBody("Oracle Application Server Forms and Reports Services") else 0
        s.found("DD-WRT") if s.inBody("DD-WRT") else 0
        s.found("Sun GlassFish Enterprise Server") if s.inHeader("server", "Sun GlassFish Enterprise Server") else 0
        s.found("Sun GlassFish Open Source Edition") if s.inHeader("server", "GlassFish Server Open Source Edition") else 0
        s.found("Default Glassfish Homepage") if s.inBody("GlassFish Server") and s.inBody("Your server is now running") else 0
        s.found("GoAhead Web Server") if s.inHeader("server", "GoAhead-Webs") else 0
        s.found("TaskTop") if s.inBody("Sign in to Tasktop") else 0
        s.found("KeyCloak") if s.inBody("Log in to Keycloak") else 0
        s.found("Apache Spark Master") if s.inBody("Spark Master") else 0
        s.found("Apache Spark Worker") if s.inBody("Spark Worker") else 0
        s.found("Werkzeug Debugger") if s.inBody("Werkzeug Debugger") else 0
        s.found("Adobe Enterprise Manager") if s.inBody("AEM") else 0
        s.found("Weblogic Application Server") if s.inBody("Welcome to Weblogic Application Server") or s.inBody("WebLogic Server") else 0 
        s.found("Spring Eureka") if s.inBody("<title>Eureka") else 0
        s.found("Python or Django Debug Pages") if s.inBody("Traceback") and s.inBody("OperationalError at /") else 0
        s.found("Xdebug") if s.inBody("xdebuginfo") or s.inBody("Xdebug") and s.inHeader("X-Xdebug-Profile-Filename", ".") else 0
        s.found("WampServer ") if s.inBody("<title>WAMPSERVER") or s.inBody("Wampserver") else 0
        s.found("Jenkins") if s.inBody("Dashboard [Jenkins]") else 0
        s.found("Swagger UI") if s.inBody("Swagger UI") else 0



        # DevOps / CI / artifact
        s.found("GitLab") if s.inBody("assets/gitlab") or s.inBody("GitLab") and s.inBody("users/sign_in") else 0
        s.found("GitLab") if s.inBody("GitLab Community Edition") else 0
        s.found("GitHub Enterprise") if s.inBody("GitHub Enterprise") or s.inBody("github-enterprise") or (s.inBody("Sign in to GitHub") and s.inBody("/session")) else 0
        s.found("Bitbucket") if s.inBody("Atlassian Bitbucket") or s.inBody("atlassian-bitbucket") or (s.inBody("Bitbucket") and s.inBody("/j_atl_security_check")) else 0
        s.found("Azure DevOps Server") if s.inBody("Azure DevOps") or s.inBody("Visual Studio Team Services") or s.inBody("/_signin") or s.inBody("/_sso") else 0

        s.found("JFrog Artifactory") if s.inBody("JFrog") and s.inBody("Artifactory") or s.inBody("/artifactory/") else 0
        s.found("Nexus Repository Manager") if s.inBody("Nexus Repository Manager") or s.inBody("Sonatype Nexus Repository") or s.inBody("nexus-repository-manager") else 0
        s.found("Harbor Registry") if s.inBody("VMware Harbor") or (s.inBody("Harbor") and s.inBody("/api/v2.0/")) else 0

        s.found("SonarQube") if s.inBody("SonarQube") or s.inBody("sonarqube") or s.inBody("/api/server/version") else 0
        s.found("Rundeck") if s.inBody("Rundeck") or s.inBody("rundeck") else 0
        s.found("Gitea") if s.inBody("Gitea: Git with a cup of tea") else 0
        s.found("RabbitMQ") if s.inBody("RabbitMQ Management") else 0
        s.found("Jupyter Notebook") if s.inBody("Jupyter Notebook") or s.inBody("JupyterLab") or s.inBody("The Jupyter Notebook") or s.inBody("data-jupyter-api-token") else 0
        s.found("Jupyter Notebook") if s.inBody("Jupyter Notebook") else 0
        s.found("Jupyter API Token") if s.inBody("data-jupyter-api-token") else 0

        s.found("Apache Zeppelin") if s.inBody("Apache Zeppelin") else 0

        s.found("Apache Airflow") if s.inBody("Apache Airflow") or s.inBody("/airflow/login") or (s.inBody("Airflow") and s.inBody("DAGs")) else 0


        s.found("MLflow") if s.inBody("mlflow-ui") else 0
        s.found("MLflow") if s.inBody("MLflow Tracking") else 0
        s.found("MLflow API") if s.inUrl("/api/2.0/mlflow") else 0

        s.found("Weights & Biases") if s.inBody("wandb") else 0
        s.found("Neptune ML") if s.inBody("neptune.ai") else 0
        s.found("Comet ML") if s.inBody("comet.ml") else 0

        s.found("Kubeflow") if s.inBody("Kubeflow") else 0
        s.found("Kubeflow Pipelines") if s.inUrl("/pipeline/apis") else 0
        s.found("Kubeflow Central Dashboard") if s.inBody("Kubeflow Central Dashboard") else 0

        s.found("Apache Airflow") if s.inBody("Apache Airflow") else 0
        s.found("Airflow DAG Graph") if s.inUrl("/graph") else 0
        s.found("Airflow DAG List") if s.inUrl("/dags") else 0

        s.found("Prefect") if s.inBody("Prefect") else 0
        s.found("Dagster") if s.inBody("Dagster") else 0
        s.found("Metaflow") if s.inBody("Metaflow") else 0

        s.found("TensorFlow Serving") if s.inUrl("/v1/models") else 0
        s.found("TensorFlow Serving") if s.inBody("model_version_status") else 0

        s.found("TorchServe") if s.inBody("TorchServe") else 0
        s.found("TorchServe Models API") if s.inUrl("/models") else 0

        s.found("Seldon Core") if s.inBody("Seldon") else 0
        s.found("KServe") if s.inBody("kserve") else 0

        s.found("BentoML") if s.inBody("BentoML") else 0
        s.found("NVIDIA Triton") if s.inBody("Triton Inference Server") else 0

        s.found("Ray Dashboard") if s.inBody("Ray Dashboard") else 0
        s.found("Ray Jobs API") if s.inUrl("/api/jobs") else 0

        s.found("NVIDIA GPU Dashboard") if s.inBody("NVIDIA GPU") else 0
        s.found("CUDA Metrics") if s.inBody("CUDA") else 0

        s.found("Prometheus GPU Metrics") if s.inBody("DCGM_FI_DEV_GPU") else 0

        s.found("Weaviate") if s.inBody("weaviate") else 0
        s.found("Weaviate Schema API") if s.inUrl("/v1/schema") else 0

        s.found("Qdrant") if s.inBody("qdrant") else 0
        s.found("Qdrant Collections API") if s.inUrl("/collections") else 0

        s.found("Milvus") if s.inBody("milvus") else 0
        s.found("ChromaDB") if s.inBody("chroma") else 0

        s.found("LangChain") if s.inBody("LangChain") else 0
        s.found("LangChain Retriever") if s.inBody("retriever") else 0
        s.found("LangChain Vectorstore") if s.inBody("vectorstore") else 0

        s.found("LlamaIndex") if s.inBody("llama_index") else 0
        s.found("Semantic Kernel") if s.inBody("semantic-kernel") else 0

        s.found("AutoGPT") if s.inBody("AutoGPT") else 0

        s.found("Apache Superset") if s.inBody("Superset") else 0
        s.found("Metabase") if s.inBody("Metabase") else 0
        s.found("Redash") if s.inBody("Redash") else 0

        s.found("Label Studio") if s.inBody("Label Studio") else 0
        s.found("CVAT") if s.inBody("CVAT") else 0
        s.found("Doccano") if s.inBody("doccano") else 0

        s.found("HuggingFace") if s.inBody("huggingface") else 0
        s.found("HuggingFace API") if s.inUrl("/api/models") else 0

        s.found("Open WebUI") if s.inBody("Open WebUI") else 0
        s.found("LibreChat") if s.inBody("LibreChat") else 0
        s.found("AnythingLLM") if s.inBody("AnythingLLM") else 0
        s.found("Dify AI") if s.inBody("Dify") else 0

        s.found("Flowise") if s.inBody("Flowise") else 0
        s.found("Langflow") if s.inBody("Langflow") else 0

        s.found("Gradio App") if s.inBody("gradio") else 0
        s.found("Streamlit App") if s.inBody("streamlit") else 0

        s.found("LiteLLM Gateway") if s.inBody("litellm") else 0
        s.found("vLLM Server") if s.inBody("vllm") else 0
        s.found("Text Generation Inference") if s.inBody("text-generation-inference") else 0

        s.found("Ollama Server") if s.inBody("Ollama") else 0

        s.found("Langfuse") if s.inBody("langfuse") else 0
        s.found("Helicone") if s.inBody("helicone") else 0
        s.found("PromptLayer") if s.inBody("promptlayer") else 0

        s.found("Phoenix AI Observability") if s.inBody("phoenix") else 0

        s.found("OpenAI-Compatible API") if s.inUrl("/v1/chat/completions") else 0
        s.found("OpenAI-Compatible API") if s.inUrl("/v1/models") else 0


        # Observability / admin
        s.found("Grafana") if s.inBody("Grafana") or s.inBody("window.grafanaBootData") or s.inBody("public/build/") else 0
        s.found("Kibana") if s.inBody("Kibana") or s.inBody("/app/kibana") or s.inBody("elastic kibana") else 0
        s.found("Splunk") if s.inBody("Splunk") and (s.inBody("/en-US/account/login") or s.inBody("Splunk Inc.")) else 0
        s.found("Prometheus") if s.inBody("Prometheus Time Series Collection") or (s.inBody("Prometheus") and (s.inBody("/graph") or s.inBody("/targets"))) else 0
        s.found("Alertmanager") if s.inBody("Alertmanager") or s.inBody("/#/alerts") else 0

        s.found("pgAdmin") if s.inBody("pgAdmin") or s.inBody("pgAdmin 4") else 0
        s.found("phpPgAdmin") if s.inBody("phpPgAdmin") else 0

        s.found("phpinfo() Page") if (s.inBody("phpinfo()") or  s.inBody("<title>phpinfo()") or (s.inBody("PHP Version") and s.inBody("System")) or (s.inBody("Configuration File (php.ini) Path") and s.inBody("Loaded Configuration File")) or s.inBody("PHP Credits") or s.inBody("Zend Engine") and s.inBody("PHP License")) else 0

        s.found("Cockpit") if s.inBody("/cockpit/") or s.inBody("Cockpit Web Service") or s.inBody("cockpit") else 0
        s.found("Webmin") if s.inBody("Webmin") or s.inBody("/session_login.cgi") else 0

        s.found("Portainer") if s.inBody("Portainer") or s.inBody("/api/auth") or s.inBody("portainer") else 0
        s.found("Rancher") if s.inBody("Rancher") or s.inBody("/v3-public/") or s.inBody("rancher") else 0
        s.found("Argo CD") if s.inBody("Argo CD") or s.inBody("/api/v1/session") else 0
        s.found("Keycloak") if s.inBody("Keycloak") or s.inBody("/realms/") else 0

        # Cloud app platforms (single-GET friendly markers)
        s.found("Azure App Service") if s.inHeader("set-cookie", "ARRAffinity") or s.inHeader("set-cookie", "ARRAffinitySameSite") or s.inBody("Azure App Service") else 0
        s.found("AWS (Elastic Beanstalk / ALB hint)") if s.inHeader("x-amzn-trace-id", "Root=") or s.inBody("AWS Elastic Beanstalk") else 0
        s.found("GCP (App Engine / trace hint)") if s.inHeader("x-cloud-trace-context", "/") or s.inBody("Google App Engine") else 0
        
        # --- Model Context Protocol (MCP) server exposure checks ---
        # MCP / Model Context Protocol obvious content
        s.found("MCP Server (Model Context Protocol)") if (
            s.inBody("Model Context Protocol") or
            s.inBody("modelcontextprotocol") or
            s.inBody("mcp server") or
            s.inBody("MCP Inspector") or
            s.inBody("MCP_PROXY_AUTH_TOKEN=")
        ) else 0

        # JSON-RPC signature (common on MCP endpoints when you hit them with GET)
        s.found("MCP JSON-RPC Surface") if (
            s.inHeader("content-type", "application/json") and
            (s.inBody("\"jsonrpc\"") and s.inBody("\"2.0\"")) and
            (s.inBody("\"error\"") or s.inBody("\"method\"") or s.inBody("\"result\""))
        ) else 0

        # Streamable HTTP MCP endpoint is commonly /mcp (or similar); many servers mention it in docs/HTML
        s.found("MCP Endpoint Mentioned") if (
            s.inBody("/mcp") and (s.inBody("json-rpc") or s.inBody("jsonrpc") or s.inBody("streamable") or s.inBody("sse"))
        ) else 0

        # SSE transport markers (older MCP HTTP+SSE setups often use /sse and /messages)
        s.found("MCP SSE Surface") if (
            s.inHeader("content-type", "text/event-stream") or
            (s.inBody("event:") and (s.inBody("data:") or s.inBody("event: endpoint") or s.inBody("event: message"))) or
            (s.inBody("/sse") and s.inBody("/messages"))
        ) else 0

        # Redirect-chain fingerprints (your redirect printing now exposes Location)
        # If the landing page redirects to an MCP-ish path, you'll see it in output,
        # but this body check catches apps that render links to common MCP endpoints.
        s.found("MCP Common Paths Referenced") if (
            s.inBody("/mcp") or
            s.inBody("/mcp/sse") or
            s.inBody("/sse") or
            s.inBody("/messages")
        ) else 0


         # --- AI / ML / LLM infrastructure (high signal, single-GET) ---
        s.found("MLflow") if (s.inBody("MLflow") and (s.inBody("mlflow-ui") or s.inBody("MLflow Tracking"))) or s.inBody("/api/2.0/mlflow") else 0

        s.found("Kubeflow") if s.inBody("Kubeflow") or s.inBody("Kubeflow Central Dashboard") else 0
        s.found("Kubeflow Pipelines") if s.inBody("/pipeline/apis") or s.inBody("Kubeflow Pipelines") else 0

        s.found("Prefect") if s.inBody("Prefect") or s.inBody("prefect-ui") else 0
        s.found("Dagster") if s.inBody("Dagster") or (s.inBody("dagster") and s.inBody("graphql")) else 0

        s.found("TensorFlow Serving") if s.inBody("model_version_status") and s.inBody("/v1/models") else 0
        s.found("TorchServe") if s.inBody("TorchServe") or (s.inBody("/models") and s.inBody("modelName")) else 0

        s.found("Ray Dashboard") if s.inBody("Ray Dashboard") or s.inBody("ray dashboard") else 0

        s.found("Weaviate") if s.inBody("weaviate") or s.inBody("/v1/graphql") else 0
        s.found("Qdrant") if s.inBody("qdrant") or (s.inBody("/collections") and s.inBody("result")) else 0
        s.found("Milvus") if s.inBody("milvus") else 0
        s.found("Chroma") if (s.inBody("chromadb") or s.inBody("Chroma")) and s.inBody("collections") else 0

        s.found("Roboflow Inference Server") if s.inTitle("Roboflow Inference Server") else 0
        s.found("Roboflow Inference Server") if s.inBody("Roboflow Inference is") else 0
        s.found("Roboflow Inference Server") if s.inBody("/notebook/start") else 0


        # --- Stealthy / modern enterprise AI surfaces ---
        s.found("Open WebUI") if s.inBody("Open WebUI") or s.inBody("open-webui") else 0
        s.found("LibreChat") if s.inBody("LibreChat") or s.inBody("librechat") else 0
        s.found("AnythingLLM") if s.inBody("AnythingLLM") or s.inBody("anything-llm") else 0
        s.found("Dify") if s.inBody("Dify") or s.inBody("dify.ai") else 0
        s.found("Flowise") if s.inBody("Flowise") or s.inBody("flowise") else 0
        s.found("Langflow") if s.inBody("Langflow") or s.inBody("langflow") else 0

        s.found("Gradio") if s.inBody("gradio") and (s.inBody("api/predict") or s.inBody("gradio-app")) else 0
        s.found("Streamlit") if s.inBody("streamlit") or s.inBody("_stcore") else 0

        # OpenAI-compatible inference / gateways (common internal copilots)
        s.found("OpenAI-Compatible API") if s.inBody("/v1/chat/completions") or s.inBody("/v1/embeddings") or (s.inBody('"object":"model"') and s.inBody('"data"')) else 0
        s.found("LiteLLM Proxy") if s.inBody("LiteLLM") or s.inBody("litellm") else 0
        s.found("vLLM OpenAI Server") if s.inBody("vLLM") or s.inBody("vllm") else 0
        s.found("TGI (text-generation-inference)") if s.inBody("text-generation-inference") or s.inBody("text_generation_inference") else 0
        s.found("Ollama") if s.inBody("ollama") or s.inBody("/api/generate") or s.inBody("/api/tags") else 0

        # LLM observability (often stores prompts/responses)
        s.found("Langfuse") if s.inBody("Langfuse") or s.inBody("langfuse") else 0
        s.found("Helicone") if s.inBody("Helicone") or s.inBody("helicone") else 0
        s.found("Phoenix (Arize)") if (s.inBody("Arize") and s.inBody("Phoenix")) or (s.inBody("phoenix") and s.inBody("llm")) else 0
        s.found("PromptLayer") if s.inBody("PromptLayer") or s.inBody("promptlayer") else 0


        s.found("Content-Security-Policy") if s.resp.get('content-security-policy') else 0
        s.found("Sentry.io CSP") if s.inHeader("content-security-policy", "sentry_key") or s.inHeader("content-security-policy", "sentry.io") else 0 # https://hackerone.com/reports/374737
        s.found("CVS directory") if s.inBody("$RCSfile:") or s.inBody("$Revision:") else 0
        

        

        # always print server header. TODO make this cleaner
        server = s.resp.get('server','')
        s.found("Server: " + server) if server else 0
        
        authn = s.resp.get('www-authenticate','')
        s.found("WWW-Authenticate: {}".format(authn)) if authn else 0

        poweredb = s.resp.get('x-powered-by', '')
        s.found("X-Powered-By: " + poweredb) if poweredb else 0

        # extract title
        tp = TitleParser()
        tp.feed( unicode(s.respdata, errors='ignore') )
        s.found("Title: {}".format(tp.title.replace("\n","").replace("\r","").lstrip(" ").rstrip(" "))) if tp.title else 0

        # parse links
        if args.links:
            lp = LinkParser()
            lp.feed( unicode(s.respdata, errors='ignore') )
            for link in lp.links:
                s.found("Link: "+ link)

    def probeUrl(self):
        #print "[*] Probing " + url
        # automatically follows 3xx
        # disable SSL validation
        h = getHttpLib()
        try:
            if args.uri: # URI scan mode ..
                self.url = self.url + args.uri
                self.resp, self.respdata = h.request(self.url)
            elif args.dav:
                self.resp, self.respdata = h.request(self.url, "PROPFIND", "<D:propfind xmlns:D='DAV:'><D:prop><D:displayname/></D:prop></D:propfind>")
            elif args.cert:
                # have to parse URL even if sometimes protocol and port info is passed in.
                parsed = urlparse(self.url)
                if args.debug:
                    print("Parsed: {} {}".format(parsed.hostname,parsed.port))
                if parsed.scheme == "https":
                    cert = None
                    port = None
                    if parsed.port is None:
                        port = 443
                    else:
                        parsed.port = 443
                    cert = ssl.get_server_certificate((parsed.hostname, port ))
                    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
                    comp = x509.get_subject().get_components()
                    debug( comp )
                    nurl = "{method}://{host}:{port}".format(method=parsed.scheme, host=comp[-1][1], port=port)
                    print( "[-] {url} | {cert} | {nurl}".format(url=self.url, cert=str( comp ), nurl=nurl ))
                    return
                else:
                    self.out("Not HTTPS")
                    return
            else:
                # Single-request profiling by default, but we can optionally follow redirects
                # while printing each 30x hop for fingerprinting.
                redirects_followed = 0
                current_url = self.url

                while True:
                    self.url = current_url
                    self.resp, self.respdata = h.request(current_url)

                    # Always print final status/URL and any 30x hops (if enabled)
                    status = int(getattr(self.resp, 'status', 0))
                    location = self.resp.get('location', '')

                    if status in (301, 302, 303, 307, 308) and location:
                        # Resolve relative redirects
                        next_url = urljoin(current_url, location)
                        self.out(f"Redirect {status} -> {next_url}")
                        
                        # Auto-tag MCP-style redirects (fingerprinting opportunity)
                        try:
                            nl = next_url.lower()
                            if (not self._mcp_redirect_tagged) and ("/mcp" in nl or "/sse" in nl or "/messages" in nl):
                                self._mcp_redirect_tagged = True
                                _prev_url = self.url
                                self.url = next_url
                                self.found("MCP Redirect")
                                self.url = _prev_url
                        except Exception:
                            pass

                        # --- Auto-tag SSO redirects ---
                        try:
                            nl = next_url.lower()

                            def tag_sso(name):
                                if name not in self._sso_redirect_tagged:
                                    self._sso_redirect_tagged.add(name)
                                    _prev_url = self.url
                                    self.url = next_url
                                    self.found(name)
                                    self.url = _prev_url

                            if ".okta.com" in nl or "/oauth2/default" in nl:
                                tag_sso("SSO Redirect (Okta)")

                            if "login.microsoftonline.com" in nl:
                                tag_sso("SSO Redirect (Entra ID)")

                            if ".auth0.com" in nl:
                                tag_sso("SSO Redirect (Auth0)")

                            if "/as/authorization.oauth2" in nl or "pingidentity" in nl:
                                tag_sso("SSO Redirect (Ping)")

                            if "/realms/" in nl:
                                tag_sso("SSO Redirect (Keycloak)")

                        except Exception:
                            pass

                        if redirects_followed >= int(args.max_redirects):
                            # Stop here; keep this 30x response as the final response
                            break

                        redirects_followed += 1
                        current_url = next_url
                        continue

                    # Not a redirect (or no location), this is the final response
                    break

                # Keep the original URL label, but also surface the effective URL when redirects were followed
                if redirects_followed > 0:
                    self.url = current_url
                    self.out(f"Final URL: {current_url}")
                self.url = current_url
            if args.debug:
                #print(self.resp)
                #print(self.respdata)
                print( json.dumps( { 
                    'url' : self.url,
                    'response': self.resp, 
                    'data': unicode( self.respdata, encoding='utf-8', errors='ignore') 
                } ) )
                #json.dumps( {'response': self.resp, 'data': unicode( self.respdata, encoding='utf-8', errors='ignore')  })
                #json.dumps( self.resp )
            if args.outputjson:
                args.outputjson.write( json.dumps( { 
                    '_type' : 'resp',
                    'url' : self.url,
                    'response': self.resp, 
                    'data': unicode( self.respdata, encoding='utf-8', errors='ignore') 
                } ))

            self.evalRules()
            if self.didFind == False:
                self.out("No Signature Match")
            else:
                self.didFind = False
        #except httplib2.SSLHandshakeError as e:
        #    error("Could create SSL connection to " + self.url)
        #    if args.debug:
        #        traceback.print_exc()
        except socket.error as e:
            error("Could not open socket to " + self.url)
            if args.debug:
                traceback.print_exc()
        except httplib2.RelativeURIError as e:
            error("Only absolute URIs are allowed (" + self.url + ")") 
            if args.debug:
                traceback.print_exc()
        except httplib2.RedirectLimit as e:
            error("Redirected more times than rediection_limit allows (" + self.url + ")")
            if args.debug:
                traceback.print_exc()
        except:
            e = sys.exc_info()[0]
            error(str(e) + " (" + self.url + ")")
            if args.debug:
                #print( e.args )
                #traceback.print_tb(sys.exc_info()[2])
                print( traceback.format_exc().splitlines()[0] )
                traceback.print_exc()

def parse():
    if args.fqdn:
        warn('Using DNS mode. Script will search for user provided hostnames in output.')
        warn('If you did not manually specify hostnames in your scan input, this might fail.')
    if(args.nmap):
        hosts = parseNmap()
        probeHosts(hosts, args.threads)
    elif(args.listfile):
        hosts = parseList()
        probeHosts(hosts, args.threads, True)
    elif(args.url):
        p = Probe()
        p.url = args.url
        p.probeUrl()
    elif(args.nessus):
        hosts = parseNessus()
        probeHosts(hosts, args.threads)

def probeHosts(hosts, numThreads=1, urlFormat=False):
    global qlock, qhosts, threads, exitFlag
    # add to queue
    # spawn workers
    for tid in range(1, numThreads+1):
        #thread = ProbeThread(tid, qhosts, urlFormat)
        debug("Starting Thread-{}".format(tid))
        thread = threading.Thread(target=process_requests, args=(tid,))
        thread.start()
        threads.append(thread)

    qlock.acquire()
    uhosts = set() # unique
    for h in hosts:
        if urlFormat is True:
            uhosts.add(h)
        else:
            uhosts.add("{method}://{host}:{port}".format(method=h['method'],host=h['host'],port=h['port']))
    for h in uhosts:
        qhosts.put(h)
    qlock.release()

    try:
        # wait
        while not qhosts.empty():
            time.sleep(.1)
        exitFlag = True
    except KeyboardInterrupt:
        exitFlag = True

    debug("All hosts completed. Should exit now...")

    # Wait for all threads to complete
    for t in threads:
        t.join()

    # TODO -- uniq hosts
    # TODO -- threads
    # TODO probe.probeUrls(hosts)
    # TODO -- spider, dir bust, CVE checks, cache output
    # TODO -- cookies

# Threading method
def process_requests(threadID):
    while not exitFlag:
        qlock.acquire()
        if not qhosts.empty():
            h = qhosts.get()
            qlock.release()
            debug( "Thread-{} : processing {}".format(threadID, h) )
            p = Probe()
            p.url = h
            p.probeUrl()
        else:
            debug("Thread-{} : queue empty... exitFlag: {}".format(threadID, exitFlag))
            qlock.release()
        time.sleep(1)


def parseNessus():
    tree = ET.parse( args.nessus)
    root = tree.getroot().find('Report')
    hosts = []
    
    for host in root.findall('ReportHost'):
        fqdn = ""
        ipaddr = ""
        for tag in host.find('HostProperties').findall('tag'):
            if tag.get('name') == 'host-fqdn':
                fqdn = tag.text
            if tag.get('name') == 'host-ip':
                ipaddr = tag.text
        for item in host.findall('ReportItem'):
            if item.get('pluginName') == 'Service Detection':
                if item.get('svc_name') == 'www':
                    port = item.get('port')
                    thehost = None
                    if args.fqdn:
                        #print fqdn, item.get('port')
                        thehost = fqdn
                    else:
                        #print ipaddr, item.get('port')
                        thehost = ipaddr
                    if port == '80':
                        hosts.append({'method':'http', 'host':thehost, 'port':port})
                    elif port == '443':
                        hosts.append({'method':'https', 'host':thehost, 'port':port})
                    else:
                        hosts.append({'method':'http', 'host':thehost, 'port':port}) # WE HOPE!
    return hosts


def parseNmap():
    tree = ET.parse( args.nmap )
    root = tree.getroot()
    hosts = []
    
    for host in root.findall('host'):
        addr = None
        if not args.fqdn:
            addr = host.find('address').get('addr')
        elif args.fqdn:
            for hostname in host.find('hostnames').findall('hostname'):
                if hostname.get('type') == 'user':
                    addr = hostname.get('name') 
        if host.find('ports') != None:
            for port in host.find('ports').findall('port'):
                portid = port.get('portid')
                if port.find('state').get('state') == 'open':
                    if port.find('service') != None:
                        if port.find('service').get('name') == 'http':
                            hosts.append({'method':'http', 'host':addr, 'port':portid})
                        if port.find('service').get('name') == 'http-proxy':
                            hosts.append({'method':'http', 'host':addr, 'port':portid})
                        if port.find('service').get('name') == 'https':
                            hosts.append({'method':'https', 'host':addr, 'port':portid})
                        if port.find('service').get('name') == 'https-alt':
                            hosts.append({'method':'https', 'host':addr, 'port':portid})
                        if port.find('service').get('name') == 'tungsten-https':
                            hosts.append({'method':'https', 'host':addr, 'port':portid})
    return hosts
        
# TODO --better parsing?
def parseList():
    urls = args.listfile.readlines()
    hosts = []
    for urln in urls:
        url = urln.rstrip()
        hosts.append(url)
    return hosts

# may add some of this functionality back in for deeper probing (dir buster style)
# also used old rules lang
# 
# def profile(url,response,data):
#     bogus = bogusSuccess(url)
#     for rule in rules:
#         found = 0
#         for test in rules[rule]['body']:
#             if data.find(test)>-1:
#                 found = found+1
#         #if not args.nofollowup:
#         # do a quick test before running path rules.
#         if not bogus:
#             for path in rules[rule]['path']:
#                 try:
#                     resp, content = getHttpLib().request(url + path,redirections=0)
#                     if resp.status == 200:
#                         print "[!] FOUND: " + url + path
#                         found = found + 1
#                 except (IOError,httplib2.RedirectLimit) as err:
#                     #print "[!] ERROR:", str(err)
#                     pass
#         if found > 0:
#             print "[!] PROFILE: " +rule+ " (" + str(found) + "/" + str(countRules(rule)) + ")"
# 
# def bogusSuccess(url):
#     try:
#         resp, content = getHttpLib().request(url + "/asdfsa/asf/sdfwe/rr344433/s/egd/xbvvvvv/",redirections=0)
#         if resp.status == 200:
#             # we almost certainly cannot trust this server's response codes
#             print "[!] WARNING: This server is responding with bogus 200 status codes. Skipping some test cases."
#             return True
#     except httplib2.RedirectLimit as e:
#         pass
#     return False

def main(argv):
    filename = ""
    parser = argparse.ArgumentParser(description='Shakedown webservices for known CMS and technology stacks - @DanAmodio')
    parser.add_argument('--nmap', type=argparse.FileType('r'), help='nmap xml file.')
    parser.add_argument('--nessus', type=argparse.FileType('r'), help='.nessus xml file.')
    parser.add_argument('-iL', '--listfile', type=argparse.FileType('r'), help='straight file list containing fully qualified urls.')
    parser.add_argument('-u', '--url', type=str, required=False, help='profile a url.')
    parser.add_argument('-o', '--output', default="default", type=str, required=False, choices=['default', 'csv', 'xml', 'json'], help='output type')
    #parser.add_argument('-oJ', type=str, help="Output JSON file name with -responses and -detections appended." )
    parser.add_argument('-oJ', '--outputjson', type=argparse.FileType('w'), help='JSON output file for raw responses and detections')
    #parser.add_argument('--subnet', type=str, required=False, help='subnet to scan.')
    #parser.add_argument('--ports', type=str, default='80,8080,8081,8000,9000,443,8443', required=False, help='the ports to scan for web services. e.g. 80,8080,443') # just use NMAP
    parser.add_argument('--fqdn', default=False, action="store_true", help='Use the fully qualified domain name from scanner output (DNS). Pretty important if doing this over the internet due to how some shared hosting services route.')
    parser.add_argument('--debug', default=False, action="store_true", help="Print the response data.")
    parser.add_argument('-t', '--threads', default=1, type=int, help='Number of concurrent request threads.')
    #parser.add_argument('--rules',default='rules',type=file,required=False,help='the rules file')
    #parser.add_argument('--nofollowup', default=False, action="store_true", help='disable sending followup requests to a host, like /wp-login.php.') # I want to avoid doing this at all with this script.
    # --fingerprint (default)
    parser.add_argument('--uri', type=str, required=False, help='get status code for a URI across all inputs. e.g. /Trace.axd')
    parser.add_argument('--dav', default=False, action="store_true", help="finger WebDav with a PROPFIND request.")
    parser.add_argument('--cert', default=False, action="store_true", help="Retrieve information from server certificate.")
    parser.add_argument('--links', default=False, action="store_true", help="Extract links from HTTP response")

    parser.add_argument('--max-redirects', default=5, type=int, help='Maximum redirects to follow (prints each 30x hop). Set 0 to never follow.')
    # TODO - http://stackoverflow.com/questions/7689941/how-can-i-retrieve-the-tls-ssl-peer-certificate-of-a-remote-host-using-python
    # http://stackoverflow.com/questions/30862099/how-can-i-get-certificate-issuer-information-in-python

    # TODO - parse stdin 
    # cat results.json | jq -s '.[] | select(.data == "Tomcat") | .url' | python3 webintel.py --stdin
    # or grep
    # grep -i Tomcat results.json | jq -c '.url' | sort | uniq | python3 webintel.py --stdin --uri /manager/html

    # cat output.json | jq 'select(._type == "found")'

    #  cat test.json | jq 'select( .data | contains("envoy") )'

    # TODO -- should i just modularize this and have a REPL / pipe functions?

    if len(argv) == 0:
        parser.print_help()
        sys.exit(0)
    try:
        global args
        args = parser.parse_args() 
        parse( )
    except IOError as err: 
        error(str(type(err)) + " : " + str(err))
        parser.print_help()
        sys.exit(2)

if __name__ == "__main__":
    main(sys.argv[1:])
