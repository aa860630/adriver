filterStrings = '''\n#include <linux/types.h>\n#include "defs.h"\n\nconst struct sfilter getsfilters[] = {\n'''
with open ("newRegex.txt") as stringsFile:
	for l in stringsFile.readlines():
		nex = l.strip().split(" ")
		filterStrings +="\t" + "{" + str(len(nex)) + ", {" 
		nex = ["\"" + f + "\"" for f in nex]
		filterStrings += ",".join(nex)
		filterStrings += " } }, \n "

filterStrings  += '''\n};\nconst size_t num_getsfilters = sizeof(getsfilters) / sizeof(getsfilters[0]);\n'''
filterStrings  += '''\nconst struct sfilter dnssfilters[] = {\n'''
with open ("dnsFilters.txt") as stringsFile:
	for l in stringsFile.readlines():
		nex = l.strip().split(" ")
		filterStrings +="\t" + "{" + str(len(nex)) + ", {" 
		nex = ["\"" + f + "\"" for f in nex]
		filterStrings += ",".join(nex)
		filterStrings += " } }, \n "

filterStrings  += '''\n};\nconst size_t num_dnssfilters = sizeof(dnssfilters) / sizeof(dnssfilters[0]);\n'''
open("filters.c","w").write(filterStrings)