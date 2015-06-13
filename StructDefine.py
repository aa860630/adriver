filterStrings = '''\n#include <linux/types.h>\n#include "defs.h"\n\nconst struct sfilter get_sfilters[] = {\n'''
with open ("newRegex.txt") as stringsFile:
	for l in stringsFile.readlines():
		nex = l.strip().split(" ")
		filterStrings +="\t" + "{" + str(len(nex)) + ", {" 
		nex = ["\"" + f + "\"" for f in nex]
		filterStrings += ",".join(nex)
		filterStrings += " } }, \n "

filterStrings  += '''\n};\nconst size_t num_get_sfilters = sizeof(get_sfilters) / sizeof(get_sfilters[0]);\n'''
filterStrings  += '''\nconst struct sfilter dns_sfilters[] = {\n'''
with open ("dnsFilters.txt") as stringsFile:
	for l in stringsFile.readlines():
		nex = l.strip().split(" ")
		filterStrings +="\t" + "{" + str(len(nex)) + ", {" 
		nex = ["\"" + f + "\"" for f in nex]
		filterStrings += ",".join(nex)
		filterStrings += " } }, \n "

filterStrings  += '''\n};\nconst size_t num_dns_sfilters = sizeof(dns_sfilters) / sizeof(dns_sfilters[0]);\n'''
open("filters.c","w").write(filterStrings)