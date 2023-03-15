#!/usr/bin/env python
# -------------------------------------------------------
#      BY: UNDEADSEC from BRAZIL :)
#      YouTube: https://www.youtube.com/c/UndeadSec
#      Github: https://github.com/UndeadSec/EvilURL
# ------------------------------------------------------
from argparse import ArgumentParser
from platform import python_version
from sys import exit, argv

from nmap import PortScanner
from whois import whois

version = python_version().startswith('2', 0, len(python_version()))
if version:
    print('Are you using python version {}\n'
          'Please, use version 3.X of python'.format(python_version()))
    exit(1)

from os import system

RED, WHITE, GREEN, END, YELLOW =\
    '\033[91m', '\33[97m', '\033[1;32m', '\033[0m', '\33[93m'

unicodes = [{'\u0430': 'Cyrillic Small Letter A'},
         {'\u03F2': 'Greek Lunate Sigma Symbol'},
         {'\u0435': 'Cyrillic Small Letter Ie'},
         {'\u043E': 'Cyrillic Small Letter O'},
         {'\u0440': 'Cyrillic Small Letter Er'},
         {'\u0455': 'Cyrillic Small Letter Dze'},
         {'\u0501': 'Cyrillic Small Letter Komi De'},
         {'\u051B': 'Cyrillic Small Letter Qa'},
         {'\u051D': 'Cyrillic Small Letter We'}]


def message(output=False):
    system('clear')
    printparser('''{0}                                                                   
{0}88888888888           88  88{1}  88        88  88888888ba   88           
{0}88                    ""  88{1}  88        88  88      "8b  88           
{0}88                        88{1}  88        88  88      ,8P  88           
{0}88aaaaa  8b       d8  88  88{1}  88        88  88aaaaaa8P'  88           
{0}88"""""  `8b     d8'  88  88{1}  88        88  88""""88'    88      v3.0     
{0}88        `8b   d8'   88  88{1}  88        88  88    `8b    88           
{0}88         `8b,d8'    88  88{1}  Y8a.    .a8P  88     `8b   88           
{0}88888888888  "8"      88  88{1}   `"Y8888Y"'   88      `8b  88888888  {1}

[ by UNDEAD{0}SEC{1} - Alisson Moretto @UndeadSec ]
\n'''.format(RED, END), output)


def cleantxt(txt):
    for i in (RED, WHITE, GREEN, END, YELLOW):
        txt = txt.replace(i, '')
    return txt


def cleanfile(output):
    arq = open(output, 'w')
    arq.write('')
    arq.close()


def checkaval(domain):
    try:
        return whois(domain).registrar
    except:
        return None


def printparser(txt, output=False):
    print(txt)
    if output:
        arq = open(output, 'a')
        arq.write(cleantxt(txt)+'\n')
        arq.close()


def printoriginal(url, checkconnection, output):
    printparser('{0}[{1}~{0}]{1} Original: {2}'.format(GREEN, END, url),
                output)
    if checkconnection: printparser(check_url(url), output)


def makeevil(char, unicd, uninum, newurl, oldurl, output):
    printparser('\n{0}[{1}*{0}]{1} Domain name: %s\n{0}[{1}*{0}]{1} Char'
                ' replaced: %s\n{0}[{1}*{0}]{1} Using Unicode:'
                ' %s\n{0}[{1}*{0}]{1} Unicode number: %s\n{0}[{1}*{0}]{1}'
                ' Evil URL: {3}%s{1}'.format(GREEN, END, YELLOW, RED) %
                (oldurl, char, unicd, uninum, newurl), output)


import itertools


def gen(url, tld, checkConnection=False, output=False, aval=False):
    url = url.lower()

    evils = [{'a': '\u0430'}, {'c': '\u03F2'}, {'e': '\u0435'},
             {'o': '\u043E'},
             {'p': '\u0440'}, {'s': '\u0455'}, {'d': '\u0501'},
             {'q': '\u051B'}, {'w': '\u051D'}]
    e_matchs = []

    for em in evils:
        if list(em)[0].upper() in url.upper():
            e_matchs.append(list(em)[0])

    cst = ''
    for ch in e_matchs:
        cst += list(ch)[0]

    words = []
    for i in range(1, 9):
        for j in itertools.combinations(cst, i):
            temp = ''.join(j)
            words.append(temp)

    for word in words:
        newurl = url
        unicd = []
        name = []
        chars = []
        for w in word:
            for em in evils:
                if list(em)[0] == w:
                    chr = em[list(em)[0]]
                    unicd.append(chr)
                    chars.append(w)
                    for u in unicodes:
                        if list(u)[0] == chr:
                            name.append(u[chr])
                    newurl = newurl.replace(w, chr)
        makeevil(chars, unicd, name, newurl + tld, url, output)
        if checkConnection: printparser(check_url(newurl+tld), output)
        if aval:
            if checkaval(newurl+tld) is None:
                printparser('{0}[{1}*{0}]{1} Available domain'
                            .format(GREEN,
                                    END),
                            output)
            else:
                printparser('{0}[{1}!{0}]{1} Unavailable domain'.format(
                    YELLOW, END), output)

# -------------- BEGIN CHECKURL MODULE----------------- #


def check_url(url):

    """
    Check connection
    :param url: suspicious url
    :return: status of connection
    """

    nmscan = PortScanner()
    result = nmscan.scan(url, arguments='-sn')

    if int(result['nmap']['scanstats']['uphosts']) > 0:
        msg = '{0}[{1}*{0}]{1} Connection test: UP'.format(GREEN, END)
    else:
        msg = '{0}[{1}!{0}]{1} Connection test: DOWN'.format(YELLOW, END)

    return msg


def check_EVIL(url):

    """
    Check evil chars in URL
    :param url: suspicious URL
    :return: result of check and the evil chars
    """

    bad_chars = ['\u0430', '\u03F2', '\u0435', '\u043E', '\u0440', '\u0455',
                 '\u0501', '\u051B', '\u051D']
    result = \
        [bad_chars[i] for i in range(len(bad_chars)) if bad_chars[i] in url]

    if result:
        msg =\
            '{0}[{1}*{0}]{1} Evil URL detected: {2}{3}{1}'.format(
                GREEN, END, RED, url)
        msg +=\
            '\n{0}[{1}*{0}]{1} Unicode characters used: {2}'.format(
                GREEN, END, result)
    else:
        msg =\
            '{0}[{1}!{0}]{1} Evil URL NOT detected: {2}'.format(
                YELLOW, END, url)

    return msg


def urls_list(file, checkConnection, output):
    """
    Read the file to verify Evil URL
    :param output:
    :param checkConnection:
    :param file: file with a list of Evil URLs
    :return: file reading
    """

    with open(file) as arq:
        urls = [f.strip() for f in arq]
    for i in range(len(urls)):
        printparser(check_EVIL(urls[i]), output)
        if checkConnection:
            printparser(check_url(urls[i]), output)
        printparser('', output)

# -------------- END CHECKURL MODULE ----------------- #


def parsehandler():
    parser = ArgumentParser(usage="evilurl.py [options]", description=
    "Generate unicode evil domains for IDN Homograph Attack and detect them.")
    parser.add_argument("-g", dest="generate", action=
    "store_true", help="Generate unicode evil domains")
    parser.add_argument("-d", dest="domain", help=
    "Domain name with termination (example.com)")
    parser.add_argument("-c", dest="checkconnection", action="store_true", help=
    "Check generated/input domain connections")
    parser.add_argument("-o", dest="output", help=
    "Save generated evil domains to a file")
    parser.add_argument("-f", dest="filepath", help=
    "Import domains from a file and check them")
    parser.add_argument("-a", dest="aval", action=
    "store_true", help="Check if domain is available")

    if len(argv) == 1:
        parser.print_help()
        exit(1)
    
    args = parser.parse_args()
    domain = '' if args.domain is None else args.domain
    generate = args.generate
    checkconnection = args.checkConnection
    filepath = args.filepath
    output = args.output
    aval = args.aval
    tld = ''
    for x in domain.split('.')[1:]:
        tld += '.' + x
    if output:
        cleanfile(output)
        message(output)
    if generate and not domain or\
            generate and domain and filepath or\
            domain and filepath:
        parser.print_help()
    elif generate and len(domain) > 0:        
        printoriginal(domain, checkconnection, output)
        gen(domain.split('.')[0], tld, checkconnection, output, aval)
    elif len(domain) > 0:
        printparser(check_EVIL(domain), output)
    elif filepath:
        urls_list(filepath, checkconnection, output)
    if checkconnection and not filepath and not generate:
        printparser(check_url(domain), output)
    if output:
        print(
            '\n{1}[{2}*{1}]{2} Logs stored to {0}'.format(output, GREEN, END))


if __name__ == '__main__':
    try:
        message()
        parsehandler()
    except KeyboardInterrupt:
        exit()
