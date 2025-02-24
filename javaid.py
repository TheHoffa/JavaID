#!/usr/bin/env python3
# -*- coding:utf-8 -*-
# Java source danger function identify program
# Original Auth by Cryin'
# Rewritten for python3 by TheHoffa

import re
import os
import sys
import optparse
from lxml import etree

class JavaID:
    def __init__(self, dir):
        self._function = ''
        self._fpanttern = ''
        self._line = 0
        self._dir = dir
        self._filename = ''
        self._vultype = ''
    
    def _run(self):
        try:
            self.banner()
            self.handle_path(self._dir)
            print("[-]【JavaID】identify danger function Finished!")
        except Exception as e:
            print(f"Error: {e}")

    def report_id(self, vul):
        print(f"[+]【{vul}】identify danger function [{self._function}] in file [{self._filename}]")

    def report_line(self):
        print(f" --> [+] on line : {self._line}")

    def handle_path(self, path):
        dirs = os.listdir(path)
        for d in dirs:
            subpath = os.path.join(path, d)
            if os.path.isfile(subpath):
                if os.path.splitext(subpath)[1] in ['.java', '.xml']:
                    self._filename = subpath
                    self.handle_file(subpath)
            else:
                self.handle_path(subpath)

    def handle_file(self, file_name):
        with open(file_name, 'r', encoding='utf-8', errors='ignore') as f:
            self._line = 0
            content = f.read()
            content = self.remove_comment(content)
            self.check_regexp(content)
    
    def function_search_line(self):
        with open(self._filename, 'r', encoding='utf-8', errors='ignore') as fl:
            self._line = 0
            import_regexp = r"import\s[^;]*;"
            while True:
                line = fl.readline()
                if not line:
                    break
                self._line += 1
                if re.search(import_regexp, line):
                    continue
                if self._function in line:
                    self.report_line()
                    continue
    
    def regexp_search(self, rule_dom, content):
        regmatch_dom = rule_dom[0].xpath("regmatch")
        regexp_doms = regmatch_dom[0].xpath("regexp") if regmatch_dom else []
        for regexp_dom in regexp_doms:
            if re.search(regexp_dom.text, content):
                self.report_id(self._vultype)
                self.function_search_line()
        return True
    
    def check_regexp(self, content):
        if not content:
            return
        self._xmlstr_dom = etree.parse('regexp.xml')
        javaid_doms = self._xmlstr_dom.xpath("javaid")
        for javaid_dom in javaid_doms:
            self._vultype = javaid_dom.get("vultype")
            function_doms = javaid_dom.xpath("function")
            for function_dom in function_doms:
                rule_dom = function_dom.xpath("rule")
                self._function = rule_dom[0].get("name")
                self.regexp_search(rule_dom, content)
        return True
    
    def remove_comment(self, content):
        return content
    
    def banner(self):
        print("[-]【JavaID】 Danger function identify tool")

if __name__ == '__main__':
    parser = optparse.OptionParser('usage: python %prog [options](eg: python %prog -d /user/java/demo)')
    parser.add_option('-d', '--dir', dest='dir', type='string', help='source code file dir')
    options, args = parser.parse_args()

    if not options.dir:
        parser.print_help()
        sys.exit()
    
    dir = options.dir
    java_identify = JavaID(dir)
    java_identify._run()
