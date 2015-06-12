filterStrings = '''\n#include <linux/types.h>\n#include "defs.h"\nstruct sfilter sfilters[] = {\n'''
with open ("newRegex.txt") as stringsFile:
	for l in stringsFile.readlines():
		nex = l.strip().split(" ")
		filterStrings +="\t" + "{" + str(len(nex)) + ", {" 
		nex = ["\"" + f + "\"" for f in nex]
		filterStrings += ",".join(nex)
		filterStrings += " } }, \n "

filterStrings  += '''\n};\nsize_t num_sfilters = sizeof(sfilters) / sizeof(sfilters[0]);\n'''
open("filters.c","w").write(filterStrings)