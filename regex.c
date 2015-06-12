#include <sys/types.h>
#include <regex.h>
#include <stdio.h>
#define REGEXES_NUMBER 13
char * regexesAsStrings[REGEXES_NUMBER] = {"washingtonpost.com*/ad/audsci.js",
"cistor.pl*/ads_files/",
"nysa.eu*/ads_files/",
"wrzesnia.pl*/ads_files/",
"74.ru*banner",
"74.ru*\"ban\"",
"74.ru*\"sb_\"",
"cbs.com*/adblock.js",
"cbs.com*/adblockr.javascript",
"/a1/*?sub=$third-party",
"/a2/?sub=$third-party",
"adtech*/addyn",
"watchever.de*/adfarm"
};


int isMatching (char * url, regex_t regexes[], unsigned int regexes_num)
{
        int reti;
	int i;
	for (i=0; regexes_num > i; ++i)
	{
		reti = regexec(&(regexes[i]), url, 0, NULL, 0);
		if( !reti ){
		        return 1;
		}
	}
	return 0;
}
//returns the number of compiled regexes
unsigned int compileRegexes(regex_t regexes[])
{
	regex_t regex;
	unsigned int regexes_num;
	int reti;
	int i;
	regexes_num = 0;
	for (i=0; REGEXES_NUMBER > i; ++i)
	{
		reti = regcomp(&regex, regexesAsStrings[i], 0);
		if( reti )
		{ 
			continue;
		}
		regexes[regexes_num] = regex;
		++regexes_num;
	}
	return regexes_num;
}


int main(int argc, char *argv[]){
        regex_t regexes[REGEXES_NUMBER];
	int reti;
	int i;
	unsigned int regcount;
	regcount = compileRegexes(regexes);
	printf("%u\n",regcount);
	if (!regcount)
	{
		reti = 1;
		goto cleanup;
	}
	/* Execute regular expression */
        if(isMatching("abc",regexes, regcount)){
                puts("Match");
        }
        else if( reti == REG_NOMATCH ){
                puts("No match");
        }
        else{
                fprintf(stderr, "Regex match failed\n");
                reti = 1;
		goto cleanup;
        }

/* Free compiled regular expression if you want to use the regex_t again */
        reti = 0;
cleanup:
	for (i=0; regcount > i; ++i)
	{
		regfree(&(regexes[i]));
	}
}
