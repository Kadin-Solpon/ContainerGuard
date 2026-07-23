#ContainerGuard

## How to use ContainerGuard
### Universal flags
1. --help: can be run on any command
2. --pdf [PATH] can be run on any command, and it will print a summary of what it did.
                harden will print the diff between the two files.
                scans will print a list of findings
3. --o, output: can only be run on SCAN commands (all except harden, for now). 
                defaults to table view (good for terminal usage)
                also able to do json format.

### Commands
1. "containerguard scan": scans a docker IMAGE for security misconfigs
2. "containerguard scan-dockerfile": scans a dockerfile for security misconfigs and base-image pinning
3. "containerguard scan-runtime": scans a running container for security misconfigs
4. "containerguard all-scans": runs commands 1-3.
5. "containerguard harden": creates a hardened dockerfile from a vulnerable one.  
   5.1.  --output [PATH]: path to write the hardened dockerfile; defaults to the directory  
                          that the vulnerable dockerfile was in, if left unspecified  
   5.2. -d, --print-diff: prints the difference (using diff) between Dockerfile.vulnerable and Dockerfile.hardened  
   5.3. the name for the hardened file is Dockerfile.hardened.   

