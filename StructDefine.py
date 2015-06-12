filterStrings = """
sfilters filters{
"""
with open ("regexes.txt") as stringsFile:
	for l in stringsFile.readlines():
		nex = l.strip().split(" ")
		filterStrings +="\t" + "{" + str(len(nex)) + ", {" 
		nex = ["\"" + f + "\"" for f in nex]
		filterStrings += ",".join(nex)
		filterStrings += " } } \n "

filterStrings  += """
};"""
open("filters.c","w").write(filterStrings)