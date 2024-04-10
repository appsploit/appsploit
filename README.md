# app-sploit

## Usage

```
❯ ./bin/release/appsploit_linux_amd64      
NAME:
   appsploit - An example sploit tool follows sploit-spec

USAGE:
   appsploit [global options] command [command options] 

COMMANDS:
   auto, a      auto gathering information, detect vulnerabilities and run exploits
   env, e       Collect information
   checksec, c  check security inside a application
   exploit, x   run a exploit
   vul, v       list vulnerabilities
   version      Show the sploit version information
   help, h      Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --proxy value    set proxy
   --timeout value  set http timeout (default: 15)
   --debug          Output information for helping debugging sploit (default: false)
   --experimental   enable experimental feature (default: false)
   --colorful       output colorfully (default: false)
   --json           output in json format (default: false)
   --help, -h       show help
```

### env: collect env information

```
❯ ./bin/release/appsploit_linux_amd64 env     
NAME:
   appsploit env - Collect information

USAGE:
   appsploit env command [command options] 

COMMANDS:
   auto          auto
   webserver, w  show webserver info
   framework, f  show framework info
   os, o         show os info
   component, c  show component list
   help, h       Shows a list of commands or help for one command

OPTIONS:
   --help, -h  show help

--------------------------
   
❯ ./bin/release/appsploit_linux_amd64 env auto
NAME:
   appsploit env auto - auto

USAGE:
   appsploit env auto [command options] [arguments...]

OPTIONS:
   --target value, -t value  target host/ip
   --port value, -p value    target port (default: 80)
   --https, -s               use https (default: false)
   --help, -h                show help

```

### checksec: check vulnerability exists

CVE-2099-9999 exists when 2 | second . 

```
❯ ./bin/release/appsploit_linux_amd64 checksec       
NAME:
   appsploit checksec - check security inside a application

USAGE:
   appsploit checksec command [command options] [arguments...]

COMMANDS:
   auto                 auto
   CVE-2099-9999, 2099  Description of CVE-2099-9999
   help, h              Shows a list of commands or help for one command

OPTIONS:
   --help, -h  show help

❯ ./bin/release/appsploit_linux_amd64 checksec 2099
[N]  CVE-2099-9999      # Description of CVE-2099-9999
```

### exploit: run exploit

CVE-2099-9999 is a vulnerability only can be exploited by root.

```
❯ ./bin/release/appsploit_linux_amd64 exploit      
NAME:
   appsploit exploit - run a exploit

USAGE:
   appsploit exploit command [command options] [arguments...]

COMMANDS:
   auto                 auto
   CVE-2099-9999, 2099  Description of CVE-2099-9999
   help, h              Shows a list of commands or help for one command

OPTIONS:
   --help, -h  show help

❯ ./bin/release/appsploit_linux_amd64 exploit 2099
ERRO[0000] CVE-2099-9999 is not exploitable             

❯ sudo ./bin/release/appsploit_linux_amd64 exploit 2099
CVE-2099-9999 has exploited
```

### vul: list vulnerabilities supported by appsploit

```
❯ ./bin/release/appsploit_linux_amd64 vul     
NAME:
   appsploit vul - list vulnerabilities

USAGE:
   appsploit vul command [command options] [arguments...]

COMMANDS:
   CVE-2099-9999, 2099  Description of CVE-2099-9999
   help, h              Shows a list of commands or help for one command

OPTIONS:
   --help, -h  show help

❯ ./bin/release/appsploit_linux_amd64 vul 2099 
NAME:
   appsploit vul CVE-2099-9999 - Description of CVE-2099-9999

USAGE:
   appsploit vul CVE-2099-9999 command [command options] [arguments...]

COMMANDS:
   checksec, c  check vulnerability exists
   exploit, x   run exploit
   help, h      Shows a list of commands or help for one command

OPTIONS:
   --help, -h  show help
```

### machine friendly output

```
❯ ./bin/release/appsploit_linux_amd64 --json env auto -t nginx.org -p 443 -s 
{"component_list":{"name":"component","description":"component list","result_list":["result-test","result-test"]},"framework":{"name":"unknown","version":"unknown"},"os":{"name":"os","description":"OS info","result":"44"},"webserver":{"name":"nginx","version":"1.25.3"}}
```