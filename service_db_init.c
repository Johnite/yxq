/*
 * service_db_init.c
 *
 *  Created on: Oct 11, 2015
 *      Author: root
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "service_db_init.h"

//注入数据的字符转化
char *cstring_unescape(char *str, unsigned int *newlen)
{
	char *dst = str, *src = str;
	char newchar;

	while(*src)
	{
		if(*src == '\\' )
		{
			src++;
			switch(*src)
			{
				case '0':
					newchar = '\0'; src++; break;
				case 'a': // Bell (BEL)
					newchar = '\a'; src++; break;
				case 'b': // Backspace (BS)
					newchar = '\b'; src++; break;
				case 'f': // Formfeed (FF)
					newchar = '\f'; src++; break;
				case 'n': // Linefeed/Newline (LF)
					newchar = '\n'; src++; break;
				case 'r': // Carriage Return (CR)
					newchar = '\r'; src++; break;
				case 't': // Horizontal Tab (TAB)
					newchar = '\t'; src++; break;
				case 'v': // Vertical Tab (VT)
					newchar = '\v'; src++; break;
				case 'x':
					src++;
					if(!*src || !*(src + 1))
					{
						return NULL;
					}
					if(!isxdigit((int) (unsigned char) *src) || !isxdigit((int) (unsigned char) *(src + 1)))
					{
						return NULL;
					}
					newchar = hex2char(*src, *(src + 1));
					src += 2;
					break;
				default:
					if(isalnum((int) (unsigned char) *src))
					{
						return NULL; // I don't really feel like supporting octals such as \015
					}
					//Other characters I'll just copy as is
					newchar = *src;
					src++;
					break;
			}
			*dst = newchar;
			dst++;
		}
		else
		{
			if(dst != src)
			{
				*dst = *src;
			}
			dst++; src++;
		}
	}

	*dst = '\0'; // terminated, but this string can include other \0, so use newlen
	if(newlen)
	{
		*newlen = dst - str;
	}
	return str;
}
//把注入数据放入probe
void setProbeString(const uint8_t *ps, int stringlen, int probe_num)
{
	if(probe_table[probe_num].probestringlen)
	{
		free(probe_table[probe_num].probestring);
	}
	probe_table[probe_num].probestringlen = stringlen;

	if(stringlen > 0)
	{
		probe_table[probe_num].probestring = (uint8_t *)safe_malloc(stringlen + 1);
		memcpy(probe_table[probe_num].probestring, ps, stringlen);
		//probe_table[probe_num].probestring[stringlen] = '\0'; // but note that other \0 may be in string
	}
	else
	{
		probe_table[probe_num].probestring = NULL;
	}
}

void *safe_malloc(size_t size)
{
	void *mymem;
	if ((int) size < 0)  /* Catch caller errors */
	{
		printf("Tried to malloc negative amount of memory!!!\n");
	}
	mymem = malloc(size);
	if (mymem == NULL)
	{
		printf("Malloc Failed! Probably out of space.\n");
	}
	return mymem;
}

void *safe_realloc(void *ptr, size_t size)
{
	void *mymem;
	if ((int) size < 0) /* Catch caller errors */
	{
		printf("Tried to realloc negative amount of memory!!\n!");
	}
	mymem = realloc(ptr, size);
	if (mymem == NULL)
	{
		printf("Realloc Failed! Probably out of space.\n");
	}
	return mymem;
}

static unsigned char hex2char(unsigned char a, unsigned char b)
{
	int val;
	if(!isxdigit((int) a) || !isxdigit((int) b))
	{
		return 0;
	}
	a = tolower((int) a);
	b = tolower((int) b);
	if(isdigit((int) a))
	{
		val = (a - '0') << 4;
	}
	else
	{
		val = (10 + (a - 'a')) << 4;
	}
	if(isdigit((int) b))
	{
		val += (b - '0');
	}
	else
	{
		val += 10 + (b - 'a');
	}
	return (unsigned char)val;
}

static char *mkstr(const char *start, const char *end)
{
	char *s;
	s = (char *)safe_malloc(end - start + 1);
	memcpy(s, start, end - start);
	s[end - start] = '\0';
	return s;
}

static char *string_prefix(char *string, const char *prefix)
{
	size_t slen, plen;
	slen = strlen(string);
	plen = strlen(prefix);
	string = (char *)safe_realloc(string, plen + slen + 1);
	memmove(string + plen, string, slen + 1);
	memmove(string, prefix, plen);
	return string;
}

//添加到端口链表中
int port_add_listnode(int probe_num, int port, enum service_tunnel_type tunnel)
{
	port_list *portnode;
	portnode = (struct port_list *)safe_malloc(sizeof(struct port_list));
	portnode->port = 0;
	portnode->ssl_port = 0;
	portnode->next = NULL;

	//添加port信息
	if(tunnel == SERVICE_TUNNEL_NONE)
	{
		portnode->port = port;
	}
	if(tunnel == SERVICE_TUNNEL_SSL)
	{
		portnode->ssl_port = port;
	}
	portnode->next = NULL;

	if(probe_table[probe_num].phead == NULL)
	{
		probe_table[probe_num].phead = portnode;
		probe_table[probe_num].ptail = probe_table[probe_num].phead;
		probe_table[probe_num].pnum++;
	}
	else
	{
		probe_table[probe_num].ptail->next = portnode;
		probe_table[probe_num].ptail = portnode;
		probe_table[probe_num].pnum++;
	}
	return 0;
}

//设置排除的端口
int setExcludePort(const char *portstr, int *exclude_port)
{
	const char *current_range;
	char *endptr;
	long int rangestart = 0, rangeend = 0;

	current_range = portstr;
	//排除的端口号的个数
	int exclude_port_num = 0;
	do{
		//去掉空格
		while(*current_range && isspace((int) (unsigned char) *current_range))
		{
			current_range++;
		}


		if(isdigit((int) (unsigned char) *current_range))
		{
			rangestart = strtol(current_range, &endptr, 10);
			if(rangestart < 0 || rangestart > 65535)
			{
				printf("Parse error of nmap-service-probes: Ports must be between 0 and 65535 inclusive\n");
			}
			current_range = endptr;
			while(isspace((int) (unsigned char) *current_range))
			{
				current_range++;
			}
		}
		else
		{
			printf("Parse error of nmap-service-probes: An example of proper portlist form is \"21-25,53,80\"\n");
		}

		//端口号转换成整形数
		/* Now I have a rangestart, time to go after rangeend *///只有一个端口的情况
		if (!*current_range || *current_range == ',')
		{
			/* Single port specification */
			rangeend = rangestart;
		}
		else if(*current_range == '-')//端口号是一个范围
		{
			current_range++;
			if(isdigit((int) (unsigned char) *current_range))
			{
				rangeend = strtol(current_range, &endptr, 10);
				if(rangeend < 0 || rangeend > 65535 || rangeend < rangestart)
				{
					printf("Parse error of nmap-service-probes: Ports must be between 0 and 65535 inclusive\n");
				}
				current_range = endptr;
			}
			else
			{
				printf("Parse error of nmap-service-probes: An example of proper portlist form is \"21-25,53,80\"\n");
			}
		}
		else
		{
			printf("Parse error of nmap-service-probes: An example of proper portlist form is \"21-25,53,80\"\n");
		}

		/* Now I have a rangestart and a rangeend, so I can add these ports */
		while(rangestart <= rangeend)
		{
			exclude_port[exclude_port_num] = rangestart;
			exclude_port_num++;
			rangestart++;
		}

		/* Find the next range */
		while(isspace((int) (unsigned char) *current_range))
		{
			current_range++;
		}
		if(*current_range && *current_range != ',')
		{
			printf("Parse error of nmap-service-probes: An example of proper portlist form is \"21-25,53,80\"\n");
		}
		if(*current_range == ',')
		{
			current_range++;
		}

	} while(current_range && *current_range);

	return exclude_port_num;

}

//设置一个probe的信息
void setProbeDetails(char *pd, int probe_num, int lineno)
{
	char *p;
	unsigned int len;
	char delimiter;

	if(!pd || !*pd)
	{
		printf("Parse error on line %d of nmap-service-probes: no arguments found!\n", lineno);
	}

	//判断fallback到哪个节点
	if (strncmp(pd, "TCP GetRequest ", 15) == 0) {

		fallback_num = probe_num;
	}

	// First the protocol
	if(strncmp(pd, "TCP ", 4) == 0)
	{
		probe_table[probe_num].probeprotocol = IPPROTO_TCP;
	}
	else if(strncmp(pd, "UDP ", 4) == 0)
	{
		probe_table[probe_num].probeprotocol = IPPROTO_UDP;
	}
	else
	{
		printf("Parse error on line %d of nmap-service-probes: invalid protocol\n", lineno);
	}
	pd += 4;
	// Next the service name//首先判断是否字符为数字或者字母当c为数字0-9或字母a-z及A-Z时，返回非零值，否则返回零。
	if(!isalnum((int) (unsigned char) *pd))
	{
		printf("Parse error on line %d of nmap-service-probes - bad probe name\n",lineno);
	}
	p = strchr(pd, ' ');
	if(!p)
	{
		printf("Parse error on line %d of nmap-service-probes - nothing after probe name\n", lineno);
	}
	len = p - pd;
	probe_table[probe_num].probename = (char *)safe_malloc(len + 1);
	memcpy(probe_table[probe_num].probename, pd, len);
	probe_table[probe_num].probename[len]  = '\0';
	// Now for the probe itself//获取注入数据
	pd = p + 1;
	if(*pd != 'q')
	{
		printf("Parse error on line %d of nmap-service-probes - probe string must begin with 'q'\n", lineno);
	}
	//分割符
	delimiter = *(++pd);
	p = strchr(++pd, delimiter);
	if(!p)
	{
		printf("Parse error on line %d of nmap-service-probes -- no ending delimiter for probe string\n", lineno);
	}
	*p = '\0';
	if(!cstring_unescape(pd, &len))
	{
		printf("Parse error on line %d of nmap-service-probes: bad probe string escaping\n", lineno);
	}
	setProbeString((const uint8_t *)pd, len, probe_num);
}
//设置端口号
void setProbablePorts(enum service_tunnel_type tunnel, const char *portstr, int lineno, int probe_num)
{
	const char *current_range;
	char *endptr;
	long int rangestart = 0, rangeend = 0;
	current_range = portstr;
	do{
		while(*current_range && isspace((int) (unsigned char) *current_range))
		{
			current_range++;
		}

		if(isdigit((int) (unsigned char) *current_range))
		{
			rangestart = strtol(current_range, &endptr, 10);
			if(rangestart < 0 || rangestart > 65535)
			{
				printf("Parse error on line %d of nmap-service-probes: Ports must be between 0 and 65535 inclusive\n", lineno);
			}
			current_range = endptr;
			while(isspace((int) (unsigned char) *current_range))
			{
				current_range++;
			}
		}
		else
		{
			printf("Parse error on line %d of nmap-service-probes: An example of proper portlist form is \"21-25,53,80\"\n", lineno);
		}

		/* Now I have a rangestart, time to go after rangeend */
		if (!*current_range || *current_range == ',')
		{
			/* Single port specification */
			rangeend = rangestart;
		}
		else if(*current_range == '-')
		{
			current_range++;
			if(isdigit((int) (unsigned char) *current_range))
			{
				rangeend = strtol(current_range, &endptr, 10);
				if(rangeend < 0 || rangeend > 65535 || rangeend < rangestart)
				{
					printf("Parse error on line %d of nmap-service-probes: Ports must be between 0 and 65535 inclusive\n", lineno);
				}
				current_range = endptr;
			}
			else
			{
				printf("Parse error on line %d of nmap-service-probes: An example of proper portlist form is \"21-25,53,80\"\n", lineno);
			}
		}
		else
		{
			printf("Parse error on line %d of nmap-service-probes: An example of proper portlist form is \"21-25,53,80\"\n", lineno);
		}

		/* Now I have a rangestart and a rangeend, so I can add these ports */
		while(rangestart <= rangeend)
		{
			//添加到端口链表中
			port_add_listnode(probe_num, rangestart, tunnel);
			rangestart++;
		}

		/* Find the next range */
		while(isspace((int) (unsigned char) *current_range))
		{
			current_range++;
		}
		if(*current_range && *current_range != ',')
		{
			printf("Parse error on line %d of nmap-service-probes: An example of proper portlist form is \"21-25,53,80\"\n", lineno);
		}
		if(*current_range == ',')
		{
			current_range++;
		}
	} while(current_range && *current_range);

}
//设置优先级
void setRarity(const char *str_ptr, int probe_num, int lineno)
{
	int tp;
	tp = atoi(str_ptr);
	if(tp<1 || tp>9)
	{
		printf("%s: Rarity directive on line %d of nmap-service-probes must be between 1 and 9\n", __func__, lineno);
	}
	probe_table[probe_num].rarity = tp;
}

static bool next_template(const char **matchtext, char **modestr, char **tmplt,char **flags, int lineno)
{
	const char *p, *q;
	char delimchar;
	p = *matchtext;
	while(isspace((int) (unsigned char) *p))
	{
		p++;
	}
	if (*p == '\0')
	{
		return false;
	}
	q = p;
	while (isalpha(*q) || *q == ':')
	{
		q++;
	}
	if (*q == '\0' || isspace(*q))
	{
		printf("%s: parse error on line %d of nmap-service-probes\n", __func__, lineno);
	}
	*modestr = mkstr(p, q);
	delimchar = *q;
	p = q + 1;
	q = strchr(p, delimchar);
	if (q == NULL)
	{
		printf("%s: parse error on line %d of nmap-service-probes\n", __func__, lineno);
	}
	*tmplt = mkstr(p, q);
	p = q + 1;
	q = p;
	while (isalpha(*q))
	{
		q++;
	}
	*flags = mkstr(p, q);
	/* Update pointer for caller. */
	*matchtext = q;
	return true;
}

//添加匹配项到probe
void addMatch(const char *matchtext, int probe_num, int lineno)
{
	struct match_list *matchnode;

	matchnode = (struct match_list *)safe_malloc(sizeof(struct match_list));

	//matchnode 初始化
	matchnode->deflineno = -1;
	matchnode->isSoft = false;
	matchnode->isInitialized = false;
	matchnode->servicename = NULL;
	//matchnode->matchstr = NULL;
	matchnode->matchops_ignorecase = false;
	matchnode->matchops_dotall = false;
	matchnode->regex_compiled = NULL;
	matchnode->regex_extra = NULL;

	matchnode->product_template = NULL;
	matchnode->version_template = NULL;
	matchnode->info_template = NULL;
	matchnode->hostname_template = NULL;
	matchnode->ostype_template = NULL;
	matchnode->devicetype_template = NULL;
	matchnode->cpe_template = NULL;
	matchnode->next = NULL;
	matchnode->regex_string = NULL;

	const char *p;
	char *modestr, *tmptemplate, *flags;
	int pcre_compile_ops = 0;
	const char *pcre_errptr = NULL;
	int pcre_erroffset = 0;
	char **curr_tmp = NULL;
	char *matchstr;

	if(matchnode->isInitialized)
	{
		printf("Sorry ... %s does not yet support reinitializion\n", __func__);
	}
	if(!matchtext || !*matchtext)
	{
		printf("%s: no matchtext passed in (line %d of nmap-service-probes)\n", __func__, lineno);
	}
	matchnode->isInitialized = true;
	matchnode->deflineno = lineno;
	while(isspace((int) (unsigned char) *matchtext))
	{
		matchtext++;
	}
	//first we find whether this is a "soft" or normal match
	if(strncmp(matchtext, "softmatch ", 10) == 0)
	{
		matchnode->isSoft = true;
		matchtext += 10;
	}
	else if(strncmp(matchtext, "match ", 6) == 0)
	{
		matchnode->isSoft = false;
		matchtext += 6;
	}
	else
	{
		printf("%s: parse error on line %d of nmap-service-probes - must begin with \"match\" or \"softmatch\"\n", __func__, lineno);
	}
	// next comes the service name
	p = strchr(matchtext, ' ');
	if (!p)
	{
		printf("%s: parse error on line %d of nmap-service-probes: could not find service name\n", __func__, lineno);
	}
	matchnode->servicename = (char *)safe_malloc(p-matchtext+1);
	memcpy(matchnode->servicename, matchtext, p-matchtext);
	matchnode->servicename[p-matchtext]  = '\0';
	// The next part is a perl style regular expression specifier
	matchtext = p;
	if(!next_template(&matchtext, &modestr, &matchstr, &flags, lineno))
	{
		printf("%s: parse error on line %d of nmap-service-probes\n", __func__, lineno);
	}
	if(strcmp(modestr, "m") != 0)
	{
		printf("%s: parse error on line %d of nmap-service-probes: matchtext must begin with 'm'\n", __func__, lineno);
	}
	matchnode->matchtype = SERVICEMATCH_REGEX;

	// any options?
	for(p = flags; *p != '\0'; p++)
	{
		if (*p == 'i')
		{
			matchnode->matchops_ignorecase = true;
		}
		else if (*p == 's')
		{
			matchnode->matchops_dotall = true;
		}
		else
		{
			printf("%s: illegal regexp option on line %d of nmap-service-probes\n", __func__, lineno);
		}
	}
	// Next we compile and study the regular expression to match
	if(matchnode->matchops_ignorecase)
	{
		pcre_compile_ops |= PCRE_CASELESS;
	}
	if(matchnode->matchops_dotall)
	{
		pcre_compile_ops |= PCRE_DOTALL;
	}
	//printf("================%s\n",matchstr);
	int matchstr_len = strlen(matchstr);
	matchnode->regex_string = (char *)calloc(1,matchstr_len+1);
	strcpy(matchnode->regex_string,matchstr);
	matchnode->regex_compiled = pcre_compile(matchstr, pcre_compile_ops, &pcre_errptr, &pcre_erroffset, NULL);
	if(matchnode->regex_compiled == NULL)
	{
		printf("%s: illegal regexp on line %d of nmap-service-probes (at regexp offset %d): %s\n", __func__, lineno, pcre_erroffset, pcre_errptr);
	}
	// Now study the regexp for greater efficiency
	matchnode->regex_extra = pcre_study(matchnode->regex_compiled, 0, &pcre_errptr);
	if (pcre_errptr != NULL)
	{
		printf("%s: failed to pcre_study regexp on line %d of nmap-service-probes: %s\n", __func__, lineno, pcre_errptr);
	}
	free(modestr);
	free(flags);

	//printf("****************matchtext =%s\n",matchtext);
	while (next_template(&matchtext, &modestr, &tmptemplate, &flags, lineno))
	{
		//printf("^^^^^^^^^^^^^^^^^^^^^^^^matchtext =%s\n",matchtext);
		//printf("$$$$$$$$$$$$$$$$$$$$$$$$tmptemplate =%s\n",tmptemplate);
		if (strcmp(modestr, "p") == 0)
		{
			matchnode->product_template = (char *)safe_malloc(128);
			memset(matchnode->product_template,'\0',128);
			memcpy(matchnode->product_template, tmptemplate, 128);
		}
		else if (strcmp(modestr, "v") == 0)
		{
			matchnode->version_template = (char *)safe_malloc(128);
			memset(matchnode->version_template,'\0',128);
			memcpy(matchnode->version_template, tmptemplate, 128);
		}
		else if (strcmp(modestr, "i") == 0)
		{
			matchnode->info_template = (char *)safe_malloc(128);
			memset(matchnode->info_template,'\0',128);
			memcpy(matchnode->info_template, tmptemplate, 128);
		}
		else if (strcmp(modestr, "h") == 0)
		{
			matchnode->hostname_template = (char *)safe_malloc(128);
			memset(matchnode->hostname_template,'\0',128);
			memcpy(matchnode->hostname_template, tmptemplate, 128);
		}
		else if (strcmp(modestr, "o") == 0)
		{
			matchnode->ostype_template = (char *)safe_malloc(128);
			memset(matchnode->ostype_template,'\0',128);
			memcpy(matchnode->ostype_template, tmptemplate, 128);
		}
		else if (strcmp(modestr, "d") == 0)
		{
			matchnode->devicetype_template = (char *)safe_malloc(128);
			memset(matchnode->devicetype_template,'\0',128);
			memcpy(matchnode->devicetype_template, tmptemplate, 128);
		}
		else if (strcmp(modestr, "cpe:") == 0)
		{
			tmptemplate = string_prefix(tmptemplate, "cpe:/");
			matchnode->cpe_template = (char *)safe_malloc(128);
			memset(matchnode->cpe_template,'\0',128);
			memcpy(matchnode->cpe_template, tmptemplate, 128);
		}
		else
		{
			printf("%s: Unknown template specifier '%s' on line %d of nmap-service-probes\n", __func__, modestr, lineno);
		}
		free(modestr);
		free(flags);
	}

	//matchnode添加到probe_table中
	if(probe_table[probe_num].mhead == NULL)
	{
		probe_table[probe_num].mhead = matchnode;
		probe_table[probe_num].mtail = probe_table[probe_num].mhead;
		probe_table[probe_num].mnum++;
	}
	else
	{
		probe_table[probe_num].mtail->next = matchnode;
		probe_table[probe_num].mtail = matchnode;
		probe_table[probe_num].mnum++;
	}
}
//
void table_print()
{
	int probe = 0;
	match_list *match_node;
	port_list *port_node;

	for(probe = 0;probe<probe_num;probe++)
	{
		//printf("**********%p %d\n",probe_table[probe].phead,probe);
		//printf("probename =%s\n",probe_table[probe].probename);



#if 1 
		//输出probe_hash基本信息
		printf("####################%d###################\n",probe);
		printf("totalwaitms = %d\n",probe_table[probe].totalwaitms);
		printf("rarity = %d\n",probe_table[probe].rarity);
		printf("probeprotocol =%d\n",probe_table[probe].probeprotocol);
		printf("probename =%s\n",probe_table[probe].probename);
		printf("probestring =%s\n",probe_table[probe].probestring);
		printf("probestringlen =%d\n",probe_table[probe].probestringlen);
		//match信息
		if(probe_table[probe].mhead != NULL)
		{
			match_node = probe_table[probe].mhead;
			while(match_node != NULL)
			{
				printf("%p\n",match_node);
				printf("%d\n",match_node->deflineno);
				printf("%d\n",match_node->isInitialized);
				printf("%d\n",match_node->isSoft);
				if(match_node->servicename != NULL)
				{
					printf("servicename:%s  ",match_node->servicename);
				}
				//输出正则表达式信息
				if(match_node->product_template != NULL)
				{
					printf("product_template =%s\n",match_node->product_template);
				}
				if(match_node->version_template != NULL)
				{
					printf("version_template =%s\n",match_node->version_template);
				}
				if(match_node->info_template != NULL)
				{
					printf("info_template =%s\n",match_node->info_template);
				}
				if(match_node->hostname_template != NULL)
				{
					printf("hostname_template =%s\n",match_node->hostname_template);
				}
				if(match_node->ostype_template != NULL)
				{
					printf("ostype_template =%s\n",match_node->ostype_template);
				}
				if(match_node->devicetype_template != NULL)
				{
					printf("devicetype_template =%s\n",match_node->devicetype_template);
				}
				if(match_node->cpe_template != NULL)
				{
					printf("cpe_template =%s\n",match_node->cpe_template);
				}
				match_node = match_node->next;
			}
		}
#endif

#if 1
		//端口列表信息
		if(probe_table[probe].phead != NULL)
		{
			port_node = probe_table[probe].phead;
			while(port_node != NULL)
			{
				//输出port信息
				if(port_node->port != 0)
				{
					printf("port =%d\n",port_node->port);
				}
				if(port_node->ssl_port != 0)
				{
					printf("ssl_port =%d\n",port_node->ssl_port);
				}
				port_node = port_node->next;
			}
		}
#endif
	}
}
//初始化数据表
void table_init()
{
#ifdef FUNC_DEBUG
	printf("[%s:%d]Enter into %s\n",__FILE__,__LINE__,__func__);
#endif
	int i;
	for(i=0; i<PROBE_TABLE_SIZE; i++)
	{
		probe_table[i].totalwaitms = 5000; //默认值
		probe_table[i].rarity = 5;
		probe_table[i].probeprotocol = -1;
		probe_table[i].probename = NULL;
		probe_table[i].probestring = NULL;
		probe_table[i].probestringlen = 0;
		probe_table[i].phead = NULL;
		probe_table[i].ptail = NULL;
		probe_table[i].pnum = 0;
		probe_table[i].mhead = NULL;
		probe_table[i].mtail = NULL;
		probe_table[i].mnum = 0;
		probe_table[i].next = NULL;
	}
}

//读取服务与版本扫描的库文件
void parse_nmap_service_probe_file()
{
#ifdef FUNC_DEBUG
	printf("[%s:%d]Enter into %s\n",__FILE__,__LINE__,__func__);
#endif
	char line[2048];
	int lineno = 0;
	probe_num = 0;
	FILE *fp;
	fp = fopen("./conf/nmap-service-probes","r");
	if(!fp)
	{
		printf("Failed to open nmap-service-probes file!\n");
	}
	while(fgets(line, sizeof(line), fp))
	{
		lineno++;
		if (*line == '\n' || *line == '#')
		{
			continue;
		}
		if (strncmp(line, "Exclude ", 8) == 0)
		{
			//排除的端口,处理以后添加
			setExcludePort(line+10, exclude_port);
#ifdef EPRINT
			int i;
			for(i=0;i<EMAX;i++)
			{
				if(exclude_port[i] != 0)
				{
					printf("exclude port is:%d\n",exclude_port[i]);
				}
			}
#endif
			continue;
		}
anotherprobe:
		if(strncmp(line, "Probe ", 6) != 0)
		{
			printf("Parse error on line %d of nmap-service-probes file!\n", lineno);
		}
		else
		{
			probe_num++;
			setProbeDetails(line+6, probe_num, lineno);//处理probe信息行
		}
		while(fgets(line, sizeof(line), fp))
		{
			lineno++;
			if(*line == '\n' || *line == '#')
			{
				continue;
			}
			if(strncmp(line, "Probe ", 6) == 0)
			{
				goto anotherprobe;
			}
			else if(strncmp(line, "ports ", 6) == 0)
			{
				setProbablePorts(SERVICE_TUNNEL_NONE, line+6, lineno, probe_num);
			}
			else if(strncmp(line, "sslports ", 9) == 0)
			{
				setProbablePorts(SERVICE_TUNNEL_SSL, line+9, lineno, probe_num);
			}
			else if(strncmp(line, "rarity ", 7) == 0)
			{
				setRarity(line+7, probe_num, lineno);
			}
			else if (strncmp(line, "fallback ", 9) == 0)//fallback关键字未处理
			{
			}
			else if(strncmp(line, "totalwaitms ", 12) == 0)
			{
				long waitms = strtol(line + 12, NULL, 10);
				if(waitms < 100 || waitms > 300000)
				{
					printf("Error on line %d of nmap-service-probes file:bad totalwaitms value. Must be between 100 and 300000 milliseconds", lineno);
				}
				probe_table[probe_num].totalwaitms = waitms;
			}
			else if(strncmp(line, "match ", 6) == 0 || strncmp(line, "softmatch ", 10) == 0)
			{
				addMatch(line, probe_num, lineno);
			}
			else if(strncmp(line, "Exclude ", 8) == 0)
			{
				printf("The Exclude directive must precede all Probes in nmap-service-probes\n");
			}
			else
			{
				printf("Parse error on line %d of nmap-service-probes file:unknown directive\n", lineno);
			}
		}
	}
	fclose(fp);
}

//新表的初始化
void table_better_init()
{

	int i = 0;
	for(i = 0;i < PROBE_BY_PORT_SIZE;i++)
	{

		Probe_Table[i].port = i;
		Probe_Table[i].tcp_num = 0;
		Probe_Table[i].udp_num = 0;


		////TCP
		Probe_Table[i].tcp_node = (probe_hash *)calloc(1,sizeof(probe_hash));
		Probe_Table[i].tcp_node->totalwaitms = 5000;
		Probe_Table[i].tcp_node->rarity = 5;
		Probe_Table[i].tcp_node->probeprotocol = -1;
		Probe_Table[i].tcp_node->probename = NULL;
		Probe_Table[i].tcp_node->probestring = NULL;
		Probe_Table[i].tcp_node->probestringlen = 0;
		Probe_Table[i].tcp_node->phead = NULL;
		Probe_Table[i].tcp_node->ptail = NULL;
		Probe_Table[i].tcp_node->pnum = 0;
		Probe_Table[i].tcp_node->mhead = NULL;
		Probe_Table[i].tcp_node->mtail = NULL;
		Probe_Table[i].tcp_node->mnum = 0;
		Probe_Table[i].tcp_node->next = NULL;

		Probe_Table[i].tcp_head = Probe_Table[i].tcp_node;
		////UDP
		Probe_Table[i].udp_node = (probe_hash *) calloc(1, sizeof(probe_hash));
		Probe_Table[i].udp_node->totalwaitms = 5000;
		Probe_Table[i].udp_node->rarity = 5;
		Probe_Table[i].udp_node->probeprotocol = -1;
		Probe_Table[i].udp_node->probename = NULL;
		Probe_Table[i].udp_node->probestring = NULL;
		Probe_Table[i].udp_node->probestringlen = 0;
		Probe_Table[i].udp_node->phead = NULL;
		Probe_Table[i].udp_node->ptail = NULL;
		Probe_Table[i].udp_node->pnum = 0;
		Probe_Table[i].udp_node->mhead = NULL;
		Probe_Table[i].udp_node->mtail = NULL;
		Probe_Table[i].udp_node->mnum = 0;
		Probe_Table[i].udp_node->next = NULL;

		Probe_Table[i].udp_head = Probe_Table[i].udp_node;

	}


	printf("=====%p\n",Probe_Table[80].tcp_node);

	ssl_port_list = (SSL_Port *)calloc(1,sizeof(SSL_Port));
	ssl_port_list->probe_node = NULL;
	ssl_port_list->ssl_port = 0;
	ssl_port_list->ssl_port_num = 0;
	ssl_port_list->next = NULL;
}

//填充信表数据
void table_better()
{

	//printf("%d\n",probe_num);
	int i;
	int ret;
	SSL_Port *ssl_head = NULL;
	int ssl_port = -1;
	//从probe_table中读取端口和probe信息存储到Probe_Table中
	for(i = 0;i < probe_num;i++)
	{

		//probe端口列表存在
		if(probe_table[i].phead != NULL)
		{
			//指向当前probe的端口列表的头指针
			struct port_list *ports_head = probe_table[i].phead;
			//获取每个端口
			while(ports_head !=  NULL)
			{
				int port = ports_head->port;

				//将该端口对应的probe放如Prob_Table中Probe链表的末尾
				if (probe_table[i].probeprotocol == IPPROTO_TCP)
				{
					if (Probe_Table[port].tcp_num == 0)
					{
						Probe_Table[port].tcp_node->totalwaitms = probe_table[i].totalwaitms;
						Probe_Table[port].tcp_node->rarity = probe_table[i].rarity;
						Probe_Table[port].tcp_node->probeprotocol = probe_table[i].probeprotocol;

						//printf("probeprotocol:--%d\n",Probe_Table[port].probe_node->probeprotocol );

						int name_len = strlen(probe_table[i].probename);
						Probe_Table[port].tcp_node->probename = (char *) calloc(1, name_len + 1);
						strcpy(Probe_Table[port].tcp_node->probename,probe_table[i].probename);

						//printf("probename:--%s\n",Probe_Table[port].probe_node->probename);

						Probe_Table[port].tcp_node->probestring =(uint8_t *) calloc(1,probe_table[i].probestringlen + 1);
						//memcpy(Probe_Table[port].probe_node->probestring,probe_table[i].probestring,probe_table[i].probestringlen);
						Probe_Table[port].tcp_node->probestring = probe_table[i].probestring;

						Probe_Table[port].tcp_node->probestringlen = probe_table[i].probestringlen;
						//printf("probestring:--%s %d\n",Probe_Table[port].probe_node->probestring,Probe_Table[i].probe_node->probestringlen);

						Probe_Table[port].tcp_node->mhead = (match_list *) calloc(1, sizeof(match_list));
						//memcpy(Probe_Table[port].probe_node->mhead,probe_table[i].mhead, sizeof(match_list));
						Probe_Table[port].tcp_node->mhead = probe_table[i].mhead;

						(Probe_Table[port].tcp_num)++;

					}
					else
					{
						//信生成一个节点
						probe_hash *new_node = (probe_hash *) calloc(1,
								sizeof(probe_hash));
						new_node->next = NULL;

						new_node->totalwaitms = probe_table[i].totalwaitms;
						new_node->rarity = probe_table[i].rarity;
						new_node->probeprotocol = probe_table[i].probeprotocol;

						//printf("probeprotocol:--%d\n",new_node->probeprotocol );

						int name_len = strlen(probe_table[i].probename);
						new_node->probename = (char *) calloc(1, name_len + 1);
						strcpy(new_node->probename, probe_table[i].probename);

						//printf("probename:--%s\n",new_node->probename);

						new_node->probestringlen =
								probe_table[i].probestringlen;
						new_node->probestring = (uint8_t *) calloc(1,
								new_node->probestringlen + 1);

						//memcpy(new_node->probestring,probe_table[i].probestring,sizeof(new_node->probestring));
						new_node->probestring = probe_table[i].probestring;
						//printf("probestringlen:--%d\n",new_node->probestringlen);

						new_node->mhead = (match_list *) calloc(1,
								sizeof(match_list));
						new_node->mhead = probe_table[i].mhead;
						//memcpy(new_node->mhead,probe_table[i].mhead, sizeof(new_node->mhead));

						/*if (new_node->mhead != NULL ) {
						 printf("%p === cpe_template:--%s\n",new_node->mhead,new_node->mhead->cpe_template);
						 } else {
						 printf("mhead == NULL:--\n");
						 }*/

						/*probe_hash *phead = Probe_Table[port].probe_node->next;

						 while(phead != NULL)
						 {
						 phead = phead->next;
						 }

						 phead = new_node;*/

						Probe_Table[port].tcp_head->next = new_node;
						Probe_Table[port].tcp_head = new_node;

						(Probe_Table[port].tcp_num)++;

					}
				}
				else if(probe_table[i].probeprotocol == IPPROTO_UDP)
				{
					if (Probe_Table[port].udp_num == 0)
					{
						Probe_Table[port].udp_node->totalwaitms =probe_table[i].totalwaitms;
						Probe_Table[port].udp_node->rarity =probe_table[i].rarity;
						Probe_Table[port].udp_node->probeprotocol =probe_table[i].probeprotocol;

						//printf("probeprotocol:--%d\n",Probe_Table[port].probe_node->probeprotocol );

						int name_len = strlen(probe_table[i].probename);
						Probe_Table[port].udp_node->probename = (char *) calloc(1, name_len + 1);
						strcpy(Probe_Table[port].udp_node->probename,probe_table[i].probename);

						//printf("probename:--%s\n",Probe_Table[port].probe_node->probename);

						Probe_Table[port].udp_node->probestring =(uint8_t *) calloc(1,probe_table[i].probestringlen + 1);
						//memcpy(Probe_Table[port].probe_node->probestring,probe_table[i].probestring,probe_table[i].probestringlen);
						Probe_Table[port].udp_node->probestring =probe_table[i].probestring;

						Probe_Table[port].udp_node->probestringlen = probe_table[i].probestringlen;
						//printf("probestring:--%s %d\n",Probe_Table[port].probe_node->probestring,Probe_Table[i].probe_node->probestringlen);

						Probe_Table[port].udp_node->mhead =(match_list *) calloc(1, sizeof(match_list));
						//memcpy(Probe_Table[port].probe_node->mhead,probe_table[i].mhead, sizeof(match_list));
						Probe_Table[port].udp_node->mhead =probe_table[i].mhead;

						(Probe_Table[port].udp_num)++;
					}
					else
					{
						//信生成一个节点
						probe_hash *new_node = (probe_hash *) calloc(1,sizeof(probe_hash));
						new_node->next = NULL;

						new_node->totalwaitms = probe_table[i].totalwaitms;
						new_node->rarity = probe_table[i].rarity;
						new_node->probeprotocol = probe_table[i].probeprotocol;

						//printf("probeprotocol:--%d\n",new_node->probeprotocol );

						int name_len = strlen(probe_table[i].probename);
						new_node->probename = (char *) calloc(1, name_len + 1);
						strcpy(new_node->probename, probe_table[i].probename);

						//printf("probename:--%s\n",new_node->probename);

						new_node->probestringlen = probe_table[i].probestringlen;
						new_node->probestring = (uint8_t *) calloc(1,new_node->probestringlen + 1);

						//memcpy(new_node->probestring,probe_table[i].probestring,sizeof(new_node->probestring));
						new_node->probestring = probe_table[i].probestring;
						//printf("probestringlen:--%d\n",new_node->probestringlen);

						new_node->mhead = (match_list *) calloc(1,sizeof(match_list));
						new_node->mhead = probe_table[i].mhead;
						//memcpy(new_node->mhead,probe_table[i].mhead, sizeof(new_node->mhead));

						Probe_Table[port].udp_head->next = new_node;
						Probe_Table[port].udp_head = new_node;

						(Probe_Table[port].udp_num)++;
					}

				}

				//输出port信息
				if (ports_head->ssl_port != 0)
				{
					ssl_port = ports_head->ssl_port;
					//printf("ssl_port =%d\n", ports_head->ssl_port);
				}

#if 1
				//判断sslport
				if(ssl_port != -1)
				{
					//在ssl链表中添加节点
					if(ssl_head == NULL)
					{

						ssl_port_list->ssl_port = ports_head->ssl_port;
						ssl_port_list->ssl_port_num++;
						ssl_port_list->probe_node = &(probe_table[i]);

						ssl_head = ssl_port_list;
					}
					else
					{
						SSL_Port *new_ssl_node = (SSL_Port *)calloc(1,sizeof(SSL_Port));
						new_ssl_node->ssl_port = ports_head->ssl_port;
						new_ssl_node->ssl_port_num++;
						new_ssl_node->probe_node = &(probe_table[i]);
						new_ssl_node->next = NULL;

						ssl_head->next = new_ssl_node;
						ssl_head = new_ssl_node;
					}

				}
#endif
				ports_head = ports_head->next;
			}

		}

	}

}

void table_better_print(){

	int i = 0;
	for(i = 0;i< PROBE_BY_PORT_SIZE;i++)
	{
		printf("port:%d  tcp_num:%d udp_num:%d\n",Probe_Table[i].port,Probe_Table[i].tcp_num,Probe_Table[i].udp_num);

		probe_hash *phead = Probe_Table[i].tcp_node;
		probe_hash *pu_head = Probe_Table[i].udp_node;

		match_list *head = phead->mhead;
		while ( head != NULL)
		{
			if(Probe_Table[i].tcp_num > 0)
			{
				printf("deflineno:%d\n",head->deflineno);
				printf("isInitialized:%d\n",head->isInitialized);
				printf("isSoft:%d\n",head->isSoft);
				if(head->servicename != NULL)
				{
					printf("servicename:%s\n",head->servicename);
				}
				printf("matchtype:%d\n",head->matchtype);
				printf("matchops_ignorecase:%d\n",head->matchops_ignorecase);
				printf("matchops_dotall:%d\n",head->matchops_dotall);
				if(head->regex_string != NULL)
				{
					printf("regex_string:%s\n",head->regex_string);
				}

				if(head->product_template != NULL)
				{
					printf("product:%s\n",head->product_template);
				}
				if(head->version_template != NULL)
				{
					printf("version:%s\n",head->version_template);
				}
				if(head->info_template != NULL)
				{
					printf("info:%s\n",head->info_template);
				}
				if(head->hostname_template != NULL)
				{
					printf("hostname:%s\n",head->hostname_template);
				}
				if(head->ostype_template != NULL)
				{
					printf("os:%s\n",head->ostype_template);
				}
				if(head->devicetype_template != NULL)
				{
					printf("device:%s\n",head->devicetype_template);
				}
				if(head->cpe_template != NULL)
				{
					printf("cpe:%s\n",head->cpe_template);
				}

			}
			head = head->next;
		}
		printf("======================\n");
		match_list *u_head = pu_head->mhead;
		/*while ( u_head != NULL)
		{
			if (Probe_Table[i].udp_num > 0)
			{
				printf("protocol:%d %s\n", u_head->probeprotocol,u_head->probename);
			}
			else
			{
				printf("null\n");
			}
			u_head = u_head->next;
		}*/
		printf("++++++++++++++++++++++\n");
	}

#if 0
	probe_hash *head = Probe_Table[80].probe_node;
	printf("probe_num:%d\n",Probe_Table[80].probe_num);
	while (head != NULL ) {

		printf("%d\n",head->totalwaitms);
		printf("%d\n",head->rarity);
		printf("%d\n",head->probeprotocol);
		printf("%s\n",head->probename);
		printf("%d\n",head->probestring);
		printf("%d\n",head->probestringlen);
		struct match_list *matchlisthead = head->mhead;
		while(matchlisthead != NULL){
			printf("%s\n", matchlisthead->servicename);
			matchlisthead = matchlisthead->next;
		}
		printf("=================\n");

		head = head->next;
	}
#endif
	printf("----------------------\n");


}

void ssl_port_print()
{

	SSL_Port *head = ssl_port_list;
	while(head)
	{
		if(head->ssl_port != 0){
			printf("SSL_PORT:%d\n", head->ssl_port);
		}
		head = head->next;
	}
}
