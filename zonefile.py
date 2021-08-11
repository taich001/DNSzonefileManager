import re
import sys
import copy
import json
import argparse
import logging
import ipaddress
from collections import defaultdict


# -------------------------------------------------------------


class ParseZoneFile:
   """
   This Class parses a zone text file an stores its contents
   in a dictionary where record types are the keys of the dictionary.
   
   print(ParseZoneFile.getdict()['a']) lists all A records of the zone file.
   All record types are stored in lower case.

   * showinput() - gives you the original zone file
   
   * showjson(Pretty=True)  - gives you the zone file in json format
   
   * getdict()   - gives you the plain dictionary
   
   supported record types are:
   '$ORIGIN', '$TTL', 'SOA', 'NS', 'A', 'AAAA', 'HINFO', 'CNAME', 'MX', 'PTR', 'TXT', 'SRV', 'URI'

   """
   def __init__(self, text, IgnoreInvalidLines=True):
      self.__input = text
      self.__lasthost = ""
      self.__current_origin = ""
      self.__current_ttl = ""
      self.__ignore_invalid = IgnoreInvalidLines
      self.__ruleerror = []
      
      self._text = text
      self._zonedict = defaultdict(list)

      self.logger = logging.getLogger(__name__)
      self.logger.setLevel(logging.DEBUG)
      file_formatter = logging.Formatter('%(asctime)s:%(message)s:')
      file_handler = logging.FileHandler('_zonefile.log')
      file_handler.setLevel(logging.INFO)
      file_handler.setFormatter(file_formatter)
      self.logger.addHandler(file_handler)

      #file_handler.setLevel(logging.ERROR)
      #file_handler.setLevel(logging.INFO)
      #logger.info('ParseZoneFile')

      self._ShakeoffComments()
      self._Levelout()
      self._CapitalLetterKeys()
      self._AddLastHost()
      self._zonedict = self._parse_lines()


   def showinput(self):
      return self.__input

   
   def showjson(self, Pretty=False):

      if Pretty:
         ret = json.dumps(self._zonedict, sort_keys=True, indent=2)
      else:
         ret = json.dumps(self._zonedict, sort_keys=True)

      return ret


   def getdict(self):
      return self._zonedict


   def validate(self):
      """
      Rule 01 - Check if one $ORIGIN is present and has valid value
      Rule 02 - Check if one $TTL is present and has valid value
      Rule 03 - Check if one @ SOA is present
      Rule 04 - Check if one @ NS is present
      Rule 05 - Check if if ttl is present and has valid values
      Rule 06 - Check if NS is behind SOA
      Rule 07 - Check if CNAME has no follower without hostname
      Rule 08 - Check if @ SOA is is valid
      Rule 09 - Check if NS is is valid
      Rule 10 - Check if MX is is valid
      Rule 11 - Check if CNAME is is valid
      Rule 12 - Check if HINFO is is valid
      Rule 13 - Check if A Record Types have valid hosts and IP
      Rule 14 - Check if AAAA Record Types have valid hosts and IP
      Rule 15 - Check if PTR is is valid
      Rule 16 - Check if TXT is is valid
      Rule 17 - Check if SRV is is valid
      Rule 18 - Check if URI is is valid

      Domain Name spec
      https://en.wikipedia.org/wiki/Domain_Name_System
      """
      self._text = self.__input
      self._ShakeoffComments()
      #lines = self._text.split("\n")
      #print("---")
      
      self._Levelout()
      #lines = self._text.split("\n")
      #print("---")

      self._Fillup()
      #lines = self._text.split("\n")
      #print("---")
      
      self._CheckRule_01() # ORIGIN
      self._CheckRule_02() # TTL
      self._CheckRule_03() # SOA
      self._CheckRule_04() # NS
      self._CheckRule_05() # TTL
      self._CheckRule_06() # SOA
      self._CheckRule_07() # CNAME
      self._CheckRule_08() # SOA
      self._CheckRule_09() # NS
      self._CheckRule_10() # MX
      self._CheckRule_11() # CNAME      
      self._CheckRule_12() # HINFO
      self._CheckRule_13() # A
      self._CheckRule_14() # AAAA
      self._CheckRule_15() # PTR
      self._CheckRule_16() # TXT
      self._CheckRule_17() # SRV
      self._CheckRule_18() # URI
            
      #lines = self._text.split("\n")
      #for line in lines:
      #   print(line)

      if len(self.__ruleerror) != 0:
         return False, self.__ruleerror
      else:
         return True, []


   def _ShakeoffComments(self):
      """
      Shake off comments from the zonefile.
      """
      ret = []
      lines = self._text.split("\n")
      for line in lines:
         if len(line.strip()) == 0:
            continue
         linetokens = self._tokenize_line(line)
         line = self._serialize(linetokens)
         ret.append(line)

      self._text = "\n".join(ret)

   
   def _Levelout(self):
      """
      Levelout the text

      Each record will be in one line.
      Shake off parenthesis.
      Change tab to space
      """
      lines = self._text.split("\n")

      # tokens: sequence of non-whitespace separated by '' where a newline was
      tokens = []
      for l in lines:
         if len(l) == 0:
            continue

         l = l.replace("\t", " ")
         l = l.replace("'", "\"")

         tokens += [x for x in l.split(" ") if len(x) > 0] + ['']

      # find (...) and turn it into a single line ("capture" it)
      capturing = False
      captured = []

      levelout = []
      while len(tokens) > 0:
         tok = tokens.pop(0)
         if not capturing and len(tok) == 0:
            # normal end-of-line
            if len(captured) > 0:
               for i in range(len(captured)):
                  if i > 0 and captured[i] == "_":
                     # this is a space placeholder at line beginning
                     # and is userless now since this line joins another 
                     # therfore will be replaced with space again
                     captured[i]= ' '
               levelout.append(" ".join(captured))
               captured = []
            continue

         if tok.startswith("("):
            # begin grouping
            tok = tok.lstrip("(")
            capturing = True

         if capturing and tok.endswith(")"):
            # end grouping.  next end-of-line will turn this sequence into a flat line
            tok = tok.rstrip(")")
            capturing = False

         captured.append(tok)

      self._text = "\n".join(levelout)


   def _Fillup(self):
      """
      Fill up line with all fields.
      host, ttl, class, recordtype, a.s.o
      if recore has no ttl global ttl will be taken
      convert time abrevations (1H -> 3600)
      convert space as first line character into '_'
      lines with invalid record types will be omitted from output
      """
      ret = []
      lines = self._text.split("\n")
      for line in lines:
         if len(line.strip()) == 0:
            continue
         if line.upper().startswith('$ORIGIN'):
            ret.append(line)
            continue
         if line.upper().startswith('$TTL'):
            tokens = self._tokenize_line(line)
            if len(tokens) > 1:
               ct = ConvertTime()
               value, terr = ct.convert(tokens[1])
               if not terr:
                  line = "$TTL " + value
            ret.append(line)
            continue
         if line.upper().startswith('@ SOA'):
            invalidline = False
            ct = ConvertTime()

            tokens = self._tokenize_line(line)
            if len(tokens) != 9:
               while len(tokens) != 9:
                  tokens.append('missing')


            line = tokens[0] + ' '
            line += tokens[1] + ' '
            line += tokens[2] + ' '
            line += tokens[3] + ' '
            line += tokens[4] + ' '

            i = 5
            while i < 9:
               value, terr = ct.convert(tokens[i])
               if terr:
                  invalidline = True
               else:
                  line += value + ' '
               i += 1


            if invalidline:
               pass
                           
            ret.append(line)
            continue

         pattern = r"(.+?)( NS | MX | A | AAAA | HINFO | CNAME | TXT | SRV | URI | PTR )(.+)"
         m = re.match(pattern, line, re.I)
         if m:
            partone = m.group(1)
            record_type = m.group(2).upper().strip()
            parameter =  m.group(3)
         else:
            partone = '### '
            self.__ruleerror.append("invalid record type! " + line)
            record_type = ''
            parameter = line

         hostname = None
         ttl = '0'
         rrclass = 'IN'
         
         lp = partone.split()
         for i in range(len(lp)):
            if lp[i] == 'IN':
               lp.pop(i)
         partone = " ".join(lp)

         pattern = r"([a-z0-9-@_]+?)*[ \t]+([0-9]*)"
         m = re.match(pattern, partone, re.I)
         if m:
            hostname = m.group(1)
            ttl = m.group(2)
         else:
            hostname = partone
            ttl = '0'

         ret.append(hostname + ' ' + ttl + ' IN ' + record_type + ' ' +parameter)
            
      self._text = "\n".join(ret)

   
   def _CapitalLetterKeys(self):
      """
      Keywords $ORIGIN and $TTL upercase
      """
      ret = []
      lines = self._text.split("\n")
      for line in lines:
         line = re.sub(r"\$[Oo][Rr][Ii][Gg][Ii][Nn] ", "$ORIGIN ", line)
         line = re.sub(r"\$[Tt][Tt][Ll] ", "$TTL ", line)
         ret.append(line)

      self._text = "\n".join(ret)

 
   def _AddLastHost(self):
      """
      Ensure that host label is defined. 
      Use last host label if there is none.
      Make record type uppercase
      """
      lines = self._text.split("\n")
      ret = []

      for line in lines:
         linetokens = self._tokenize_line(line)
         if len(linetokens) == 0:
            continue

         if line.startswith("$"):
            ret.append(line)
            continue

         if line.startswith("@ SOA"):
            ret.append(line)
            self.__lasthost = '@'
            continue

         pattern = r"(.+?)( NS | MX | A | AAAA | HINFO | CNAME | TXT | SRV | URI | PTR )(.+)"
         m = re.match(pattern, line, re.I)
         if m:
            partone = m.group(1)
            record_type = m.group(2).upper().strip()
            parameter =  m.group(3)
         else:
            partone = ''
            hostname = ''
            ttl = ''
            record_type = ''
            parameter = ''

         
         if len(partone) > 0:

            hostname = ''
            ttl = '0'
            rrclass = 'IN'

            lp = partone.split()
            for i in range(len(lp)):
               if lp[i] == 'IN':
                  lp.pop(i)
            partone = " ".join(lp)

            pattern = r"([a-z0-9-@_]+?)*[ \t]+([0-9]*)"
            m = re.match(pattern, partone, re.I)
            if m:
               hostname = m.group(1)
               ttl = m.group(2)
            else:
               hostname = partone
               ttl = '0'

         if hostname == '_':
            hostname = self.__lasthost
         else:
            self.__lasthost = hostname
         
         if len(record_type) != 0:
            ret.append(hostname + ' ' + ttl + ' ' + record_type + ' ' + parameter)

      self._text = "\n".join(ret)


   def _parse_lines(self):
      """
      Parse a zonefile into a dict.
      each record must be on one line.
      all comments must be removed.
      """

      self._zonedict = defaultdict(list)
      record_lines = self._text.split("\n")
      myparser = self._ckeck_records()

      for record_line in record_lines:
         record_token = self._tokenize_line(record_line)
         try:
            self._zonedict = self._parse_line(myparser, record_token, self._zonedict)
         except InvalidLineException:
            self.logger.warning('Invalid Line! ' + self.__current_origin + ' ' + record_line)

      return self._zonedict


   def _parse_line(self, myparser, record_token, parsed_records):
      """
      Given the parser, capitalized list of a line's tokens, and the current set of records
      parsed so far, parse it into a dictionary.

      Return the new set of parsed records.
      """

      ct = ConvertTime()
      if record_token[0].upper() == '$TTL':
         record_token[1], terr = ct.convert(record_token[1])
         if terr:
            self.logger.warning('Invalid Time! ' + self.__current_origin + ' in $TTL Time is set to 86400')
         else:
            self._current_ttl = record_token[1]

      if record_token[0] == '@':
         if record_token[1].upper() == 'SOA':
            record_token[5], terr = ct.convert(record_token[5])
            if terr:
               self.logger.warning('Invalid Time! ' + self.__current_origin + ' in SOA! Time is set to 86400')

            record_token[6], terr = ct.convert(record_token[6])
            if terr:
               self.logger.warning('Invalid Time! ' + self.__current_origin + ' in SOA! Time is set to 86400')

            record_token[7], terr = ct.convert(record_token[7])
            if terr:
               self.logger.warning('Invalid Time! ' + self.__current_origin + ' in SOA! Time is set to 86400')

            record_token[8], terr = ct.convert(record_token[8])
            if terr:
               self.logger.warning('Invalid Time! ' +  self.__current_origin + ' in SOA! Time is set to 86400')

      if record_token[0].upper() == '$ORIGIN':
         self.__current_origin = record_token[1]

      line = " ".join(record_token)

      # match parser to record type
      if len(record_token) >= 2 and record_token[1] in SUPPORTED_RECORDS:
         # with no ttl
         record_token = [record_token[1]] + record_token
      elif len(record_token) >= 3 and record_token[2] in SUPPORTED_RECORDS:
         # with ttl
         record_token = [record_token[2]] + record_token
         if record_token[0] == "TXT":
            record_token = record_token[:2] + ["--ttl"] + record_token[2:]
      try:
         rr, unmatched = myparser.parse_known_args(record_token)
         # assert len(unmatched) == 0, "Unmatched fields: %s" % unmatched

      except (SystemExit, AssertionError, InvalidLineException):
         # invalid argument
         self.logger.warning('Invalid record type! ' + self.__current_origin + ' ' + line)
         raise InvalidLineException(line)

      record_dict = rr.__dict__
      if record_token[0] == "TXT" and len(record_dict['txt']) == 1:
         record_dict['txt'] = record_dict['txt'][0]

      # what kind of record? including origin and ttl
      record_type = None
      for key in list(record_dict.keys()):
         if key in SUPPORTED_RECORDS and (key.startswith("$") or record_dict[key] == key):
            record_type = key
            if record_dict[key] == key:
                  del record_dict[key]
            break

      # clean fields
      for field in list(record_dict.keys()):
         if record_dict[field] is None:
            del record_dict[field]

      # special record-specific fix-ups
      if record_type == 'PTR':
         record_dict['fullname'] = record_dict['name'] + '.' + self.__current_origin

      if len(record_dict) > 0:
         if record_type.startswith("$"):
            # put the value directly
            record_dict_key = record_type.lower()
            parsed_records[record_dict_key] = record_dict[record_type]
         else:
            record_dict_key = record_type.lower()
            parsed_records[record_dict_key].append(record_dict)
 
      return parsed_records


   def _tokenize_line(self, line):
      """
      Tokenize a line:
      * split tokens on whitespace
      * treat quoted strings as a single token
      * drop comments
      * handle escaped spaces and comment delimiters
      """
      ret = []
      escape = False
      quote = False
      tokenbuffer = ""
      if type(line) != str:
           return ret
      linechars = list(line)

      if linechars[0] == ' ' or ord(linechars[0]) == 9: # tab
         firstblank = True
      else:
         firstblank = False

      while len(linechars) > 0:
         char = linechars.pop(0)
         if char.isspace():
            if not quote and not escape:
               # end of token
               if len(tokenbuffer) > 0:
                  ret.append(tokenbuffer)

               tokenbuffer = ""
            elif quote:
               # in quotes
               tokenbuffer += char
            elif escape:
                # escaped space
                tokenbuffer += char
                escape = False
            else:
                tokenbuffer = ""

            continue

         if char == '\\':
            escape = True
            continue
         elif char == '"':
            if not escape:
               if quote:
                  # quote ends
                  ret.append(tokenbuffer)
                  tokenbuffer = ""
                  quote = False
                  continue
               else:
                  # quote beginning
                  quote = True
                  continue
         elif char == ';':
            if not escape and not quote:
               ret.append(tokenbuffer)
               tokenbuffer = ""
               break

         # normal character
         tokenbuffer += char
         escape = False

      if len(tokenbuffer.strip(" ").strip("\n")) > 0:
         ret.append(tokenbuffer)

      if firstblank:
         # there was a space at the beginning of the line
         # it will be preserved as a '_' char, and latter changed back again
         ret.insert(0, '_')

      return ret


   def _serialize(self, tokens):
      """
      Serialize tokens:
      * quote whitespace-containing tokens
      * escape semicolons
      """

      ret = []
      for tok in tokens:
         if " " in tok:
            tok = '"%s"' % tok

         if chr(9) in tok:
            tok = '"%s"' % tok
            
         if ";" in tok:
            tok = tok.replace(";", "\;")

         ret.append(tok)

      return " ".join(ret)


   def _ckeck_records(self):
      """
      Make an ArgumentParser that accepts DNS RRs
      """
      line_parser = ZonefileLineParser()
      subparsers = line_parser.add_subparsers()

      # parse $ORIGIN
      sp = subparsers.add_parser("$ORIGIN")
      sp.add_argument("$ORIGIN", type=str)

      # parse $TTL
      sp = subparsers.add_parser("$TTL")
      sp.add_argument("$TTL", type=int)

      # parse each RR
      args_and_types = [
         ("mname", str), ("rname", str), ("serial", int), ("refresh", int),
         ("retry", int), ("expire", int), ("minimum", int)
      ]
      self._make_rr_subparser(subparsers, "SOA", args_and_types)

      self._make_rr_subparser(subparsers, "NS", [("host", str)])
      self._make_rr_subparser(subparsers, "A", [("ip", str)])
      self._make_rr_subparser(subparsers, "AAAA", [("ip", str)])
      self._make_rr_subparser(subparsers, "CNAME", [("alias", str)])
      self._make_rr_subparser(subparsers, "MX", [("preference", str), ("host", str)])
      self._make_txt_subparser(subparsers)
      self._make_rr_subparser(subparsers, "PTR", [("host", str)])
      self._make_rr_subparser(subparsers, "SRV", [("priority", int), ("weight", int), ("port", int), ("target", str)])
      self._make_rr_subparser(subparsers, "URI", [("priority", int), ("weight", int), ("target", str)])
      self._make_rr_subparser(subparsers, "HINFO", [("cpu", str), ("system", str)])

      return line_parser


   def _make_rr_subparser(self, subparsers, rec_type, args_and_types):
      """
      Make a subparser for a given type of DNS record
      """
      sp = subparsers.add_parser(rec_type)

      sp.add_argument("name", type=str)
      sp.add_argument("ttl", type=int, nargs='?')
      sp.add_argument(rec_type, type=str)

      for my_spec in args_and_types:
         (argname, argtype) = my_spec[:2]
         if len(my_spec) > 2:
            nargs = my_spec[2]
            sp.add_argument(argname, type=argtype, nargs=nargs)
         else:
            sp.add_argument(argname, type=argtype)
      return sp


   def _make_txt_subparser(self, subparsers):
      sp = subparsers.add_parser("TXT")

      sp.add_argument("name", type=str)
      sp.add_argument("--ttl", type=int)
      sp.add_argument("TXT", type=str)
      sp.add_argument("txt", type=str, nargs='+')
      return sp


   def _CheckRule_01(self):
      """
      Check if one $ORIGIN is present and has valid value
      """
      counter = 0
      lines = self._text.split("\n")
      for line in lines:
         if len(line) == 0:
            continue
         if line.upper().startswith('$ORIGIN'):
            counter += 1
            words = line.split(' ')
            if len(words) == 2:
               if not self.__check_hostname(words[1]):
                  self.__ruleerror.append("$origin domain name not valid.")
                  break
            else:
               self.__ruleerror.append("$origin domain name not valid.")
               break
      
      if counter != 1:
         self.__ruleerror.append("$origin should be present exactly once.")


   def _CheckRule_02(self):
      """
      Check if one $TTL is present and has valid value
      """
      counter = 0
      ct = ConvertTime()   
      lines = self._text.split("\n")
      for line in lines:
         if line.upper().startswith('$TTL'):
            counter += 1
            words = line.split(' ')
            if len(words) == 2:
               value = words[1]
               value, timeerror = ct.convert(value)
               if timeerror:
                  self.__ruleerror.append("$ttl value not valid.")
                  continue
               if not self.__check_number(value):
                  self.__ruleerror.append("$ttl value not valid.")
                  continue
            else:
               self.__ruleerror.append("$ttl not valid.")
               continue
      
      if counter != 1:
         self.__ruleerror.append("$ttl should be present exactly once.")


   def _CheckRule_03(self):
      """
      Check if one @ SOA is present
      """
      counter = 0
      lines = self._text.split("\n")
      for line in lines:
         if len(line) == 0:
            continue
         if line.upper().startswith('@ SOA'):
            counter += 1
      
      if counter != 1:
         self.__ruleerror.append("@ SOA must be present exactly once.")


   def _CheckRule_04(self):
      """
      Check if one @ NS is present
      """
      counter = 0
      lines = self._text.split("\n")
      for line in lines:
         if len(line) == 0:
            continue

         pattern = r".+?[ \t](IN NS)[ \t].*"
         m = re.match(pattern, line, re.I)
         if m:
            counter += 1
      
      if counter < 1:
         self.__ruleerror.append("@ NS must be present once.")


   def _CheckRule_05(self):
      """
      Check if ttl of records are valid
      """
      counter = 0
      lines = self._text.split("\n")
      for line in lines:
         if len(line) == 0:
            continue

         pattern = r".+?[ \t]([0-9]+)[ \t]+IN.+"
         m = re.match(pattern, line, re.I)
         if m:
            ttl = m.group(1)
            if not self.__check_number(ttl):
               self.__ruleerror.append("ttl not valid! " + line)


   def _CheckRule_06(self):
      """
      Check if NS without host is behind SOA
      """
      lines = self._text.split("\n")
      counter = 0
      status = 0
      for i in range(len(lines)):
         line = lines[i]
         if status == 0:
            pattern = r"(@ SOA ).+"
            m = re.match(pattern, lines[i], re.I)
            if m:
               status = 1;
               continue

         if status == 1:
            pattern = r"[@_](.*) IN [MX|TXT|A|AAAA|HINFO|PTR|SRV|URI] .*"
            m = re.match(pattern, lines[i], re.I)
            if not m:
               status = 2
               print(m)

         if status == 2:
            pattern = r"[@_](.*?) IN NS .+"
            m = re.match(pattern, lines[i], re.I)
            if m:
               counter += 1
               nsrec = i

      if counter < 1:
         self.__ruleerror.append("there is no valid NS record after SOA!")


   def _CheckRule_07(self):
      """
      Check if CNAME has no follower without hostname
      """
      lines = self._text.split("\n")

      for line in lines:
         print(line)


      counter = 0
      status = 0
      for line in lines:
         if status == 0:
            pattern = r".+?[ \t]IN CNAME.+"
            m = re.match(pattern, line, re.I)
            if m:
               status = 1
         if status == 1:
            pattern = r"(_).+"
            m = re.match(pattern, line, re.I)
            if m:
               self.__ruleerror.append("cname follower without a hostname! " + line)
            status = 0


   def _CheckRule_08(self):
      """
      Check if @ SOA is is valid
      """
      lines = self._text.split("\n")
      ct = ConvertTime()

      status = 0
      for line in lines:
         if status == 0:
            pattern = r"(@ SOA)[ \t]+.+"
            m = re.match(pattern, line, re.I)
            if m:
               break

      linetokens = self._tokenize_line(line)
      if len(linetokens) != 9:
         self.__ruleerror.append("wrong SOA record! " + line)
      else:
         if linetokens[0] != '@':
            self.__ruleerror.append("wrong SOA record! " + line)

         if linetokens[1] != 'SOA':
            self.__ruleerror.append("wrong SOA record! " + line)
            
         master_name = linetokens[2]
         if not self.__check_hostname(master_name):
            self.__ruleerror.append("wrong master name in SOA record! " + line)

         responsible_name = linetokens[3]
         if not self.__check_hostname(responsible_name):
            self.__ruleerror.append("wrong responsible name in SOA record! " + line)

         serial = linetokens[4]
         if not self.__check_number(serial):
            self.__ruleerror.append("wrong serial in SOA record! " + line)

         i = 5
         while i < 9:
            value = linetokens[i]
            error_convert = False
            value, error_convert = ct.convert(value)
            if not self.__check_number(value):
               self.__ruleerror.append("wrong time value in SOA record! " + line)
            i += 1


   def _CheckRule_09(self):
      """
      Check if NS is is valid
      """
      lines = self._text.split("\n")
      status = 0
      for line in lines:
         if status == 0:
            pattern = r".+?[ \t]IN NS.+"
            m = re.match(pattern, line, re.I)
            if m:
               status = 1
         if status == 1:
            linetokens = self._tokenize_line(line)
            if len(linetokens) != 5:
               self.__ruleerror.append("wrong NS record! " + line)
            if linetokens[0].startswith('@') or linetokens[0].startswith('_'):
               pass
            else:
               if not self.__check_hostname(linetokens[0]):
                  self.__ruleerror.append("wrong NS record! " + line)
            if not self.__check_number(linetokens[1]):
               self.__ruleerror.append("wrong NS record! " + line)
            if not self.__check_hostname(linetokens[4]):
               self.__ruleerror.append("wrong NS record! " + line)
            status = 0


   def _CheckRule_10(self):
      """
      Check if MX is is valid
      """
      lines = self._text.split("\n")
      status = 0
      for line in lines:
         if status == 0:
            pattern = r".+?[ \t]IN MX.+"
            m = re.match(pattern, line, re.I)
            if m:
               status = 1
         if status == 1:
            linetokens = self._tokenize_line(line)
            if len(linetokens) != 6:
               self.__ruleerror.append("wrong MX record! " + line)
            if linetokens[0].startswith('@') or linetokens[0].startswith('_'):
               pass
            else:
               if not self.__check_hostname(linetokens[0]):
                  self.__ruleerror.append("wrong MX record! " + line)
            if not self.__check_number(linetokens[1]):
               self.__ruleerror.append("wrong MX record! " + line)
            if not self.__check_number(linetokens[4]):
               self.__ruleerror.append("wrong MX record! " + line)
            if not self.__check_hostname(linetokens[5]):
               self.__ruleerror.append("wrong MX record! " + line)
            status = 0


   def _CheckRule_11(self):
      """
      Check if CNAME is is valid
      """
      lines = self._text.split("\n")
      status = 0
      for line in lines:
         if status == 0:
            pattern = r".+?[ \t]IN CNAME.+"
            m = re.match(pattern, line, re.I)
            if m:
               status = 1
         if status == 1:
            linetokens = self._tokenize_line(line)
            if len(linetokens) != 5:
               self.__ruleerror.append("wrong CNAME record! " + line)
            if not self.__check_hostname(linetokens[0]):
               self.__ruleerror.append("wrong CNAME record! " + line)
            if not self.__check_number(linetokens[1]):
               self.__ruleerror.append("wrong CNAME record! " + line)
            if not self.__check_hostname(linetokens[4]):
               self.__ruleerror.append("wrong CNAME record! " + line)
            status = 0


   def _CheckRule_12(self):
      """
      Check if HINFO is is valid
      """
      lines = self._text.split("\n")
      status = 0
      for line in lines:
         if status == 0:
            pattern = r".+?[ \t]IN HINFO.+"
            m = re.match(pattern, line, re.I)
            if m:
               status = 1
         if status == 1:
            linetokens = self._tokenize_line(line)
            if len(linetokens) != 6:
               self.__ruleerror.append("wrong HINFO record! " + line)
            if linetokens[0].startswith('@') or linetokens[0].startswith('_'):
               pass
            else:
               if not self.__check_hostname(linetokens[0]):
                  self.__ruleerror.append("wrong HINFO record! " + line)
            if not self.__check_number(linetokens[1]):
               self.__ruleerror.append("wrong HINFO record! " + line)
            status = 0


   def _CheckRule_13(self):
      """
      Check if A Record Types have valid host and IP
      """
      lines = self._text.split("\n")
      status = 0
      for line in lines:
         if status == 0:
            pattern = r".+?( IN A ).+"
            m = re.match(pattern, line, re.I)
            if m:
               status = 1
         if status == 1:
            linetokens = self._tokenize_line(line)
            if len(linetokens) != 5:
               self.__ruleerror.append("wrong A record! " + line)
            if linetokens[0].startswith('@') or linetokens[0].startswith('_'):
               pass
            else:
               if not self.__check_hostname(linetokens[0]):
                  self.__ruleerror.append("wrong A record! " + line)
            if not self.__check_number(linetokens[1]):
               self.__ruleerror.append("wrong A record! " + line)
            if not self.__check_ipv4(linetokens[4]):
               self.__ruleerror.append("wrong A record! " + line)

            status = 0


   def _CheckRule_14(self):
      """
      Check if AAAA Record Types have valid host and IP
      """
      lines = self._text.split("\n")
      status = 0
      for line in lines:
         if status == 0:
            pattern = r".+?[ \t]IN AAAA.+"
            m = re.match(pattern, line, re.I)
            if m:
               status = 1
         if status == 1:
            linetokens = self._tokenize_line(line)
            if len(linetokens) != 5:
               self.__ruleerror.append("wrong AAAA record! " + line)
            if linetokens[0].startswith('@') or linetokens[0].startswith('_'):
               pass
            else:
               if not self.__check_hostname(linetokens[0]):
                  self.__ruleerror.append("wrong AAAA record! " + line)
            if not self.__check_number(linetokens[1]):
               self.__ruleerror.append("wrong AAAA record! " + line)
            if not self.__check_ipv6(linetokens[4]):
               self.__ruleerror.append("wrong AAAA record! " + line)

            status = 0


   def _CheckRule_15(self):
      """
      Check if PTR is is valid
      """
      lines = self._text.split("\n")
      status = 0
      for line in lines:
         if status == 0:
            pattern = r".+?[ \t]IN PTR.+"
            m = re.match(pattern, line, re.I)
            if m:
               status = 1
         if status == 1:
            linetokens = self._tokenize_line(line)
            if len(linetokens) != 5:
               self.__ruleerror.append("wrong PTR record! " + line)
            if linetokens[0].startswith('@') or linetokens[0].startswith('_'):
               pass
            else:
               if not self.__check_hostname(linetokens[0]):
                  self.__ruleerror.append("wrong PTR record! " + line)
            if not self.__check_number(linetokens[1]):
               self.__ruleerror.append("wrong PTR record! " + line)
            if not self.__check_hostname(linetokens[4]):
               self.__ruleerror.append("wrong PTR record! " + line)
            status = 0


   def _CheckRule_16(self):
      """
      Check if TXT is is valid
      """
      lines = self._text.split("\n")
      status = 0
      for line in lines:
         if status == 0:
            pattern = r".+?[ \t]IN TXT.+"
            m = re.match(pattern, line, re.I)
            if m:
               status = 1
         if status == 1:
            linetokens = self._tokenize_line(line)
            if len(linetokens) != 5:
               self.__ruleerror.append("wrong TXT record! " + line)
            if linetokens[0].startswith('@') or linetokens[0].startswith('_'):
               pass
            else:
               if not self.__check_hostname(linetokens[0]):
                  self.__ruleerror.append("wrong TXT record! " + line)
            if not self.__check_number(linetokens[1]):
               self.__ruleerror.append("wrong TXT record! " + line)

            status = 0


   def _CheckRule_17(self):
      """
      Check if SRV is is valid
      """
      lines = self._text.split("\n")
      status = 0
      for line in lines:
         if status == 0:
            pattern = r".+?[ \t]IN SRV.+"
            m = re.match(pattern, line, re.I)
            if m:
               status = 1
         if status == 1:
            linetokens = self._tokenize_line(line)
            if len(linetokens) != 8:
               self.__ruleerror.append("wrong SRV record! " + line)
            if linetokens[0].startswith('@') or linetokens[0].startswith('_'):
               pass
            else:
               if not self.__check_hostname(linetokens[0]):
                  self.__ruleerror.append("wrong SRV record! " + line)
            if not self.__check_number(linetokens[1]):
               self.__ruleerror.append("wrong SRV record! " + line)

            try:
               value = int(linetokens[4]) # priority
               if value < 0 or value > 65535:
                  self.__ruleerror.append("wrong SRV record! " + line)
            except:
               self.__ruleerror.append("wrong SRV record! " + line)

            try:
               value = int(linetokens[5]) # weight
               if value < 0 or value > 65535:
                  self.__ruleerror.append("wrong SRV record! " + line)
            except:
               self.__ruleerror.append("wrong SRV record! " + line)

            try:
               value = int(linetokens[6]) # port
               if value < 0 or value > 65535:
                  self.__ruleerror.append("wrong SRV record! " + line)
            except:
               self.__ruleerror.append("wrong SRV record! " + line)

            if not self.__check_hostname(linetokens[7]): # target host
               self.__ruleerror.append("wrong SRV record! " + line)

            status = 0


   def _CheckRule_18(self):
      """
      Check if URI is is valid
      """
      lines = self._text.split("\n")
      status = 0
      for line in lines:
         if status == 0:
            pattern = r".+?[ \t]IN URI.+"
            m = re.match(pattern, line, re.I)
            if m:
               status = 1
         if status == 1:
            linetokens = self._tokenize_line(line)
            if len(linetokens) != 7:
               self.__ruleerror.append("wrong URI record! " + line)
            if linetokens[0].startswith('@') or linetokens[0].startswith('_'):
               pass
            else:
               if not self.__check_hostname(linetokens[0]):
                  self.__ruleerror.append("wrong URI record! " + line)
            if not self.__check_number(linetokens[1]):
               self.__ruleerror.append("wrong URI record! " + line)

            try:
               value = int(linetokens[4]) # priority
               if value < 0 or value > 65535:
                  self.__ruleerror.append("wrong SRV record! " + line)
            except:
               self.__ruleerror.append("wrong SRV record! " + line)

            try:
               value = int(linetokens[5]) # weight
               if value < 0 or value > 65535:
                  self.__ruleerror.append("wrong SRV record! " + line)
            except:
               self.__ruleerror.append("wrong SRV record! " + line)

            status = 0


   def __check_hostname(self, hostname):
      """
      Check if given hostname meets criteria
      """
      if hostname[-1] == ".":
         # strip exactly one dot from the right, if present
         hostname = hostname[:-1]

      if len(hostname) > 253:
         ret = False

      labels = hostname.split(".")

      # the TLD must be not all-numeric
      if re.match(r"[0-9]+$", labels[-1]):
         ret = False

      # label must not be longer than 63 char
      # and must not start or end with a hyphen
      allowed = re.compile(r"(?!-)[a-z0-9-]{1,63}(?<!-)$", re.IGNORECASE)
      if (all(allowed.match(label) for label in labels)):
         ret = True
      else:
         ret = False

      return ret


   def __check_number(self, token):
      """
      Check if given number is in range.
      between null and 2**31
      """
      try:
         value = int(token)
         if value >= 0 and value <= 2**31:
            ret = True
      except:
         ret = False
      
      return ret


   def __check_ipv4(self, ipv4):
      """
      Check if given txt is a vild ipv4 address.
      e.g. 192.168.0.1
      """
      if type(ipv4) != str:
         return False

      if ipv4.count(".") != 3:
         return False

      ret = True
      parts = ipv4.split('.')
      for part in parts:
         try:
            num = int(part)
            if num < 0 or num > 255:
               ret = False
         except:
            ret = False
      
      return ret


   def __check_ipv6(self, ipv6):
      """
      Check if given txt is a vild ipv6 address.
      e.g. 2001:4860:4860::8888
      """
      if type(ipv6) != str:
         return False

      try:
         ipv6addr = ipaddress.ip_address(ipv6)
         value = ipaddress.ip_address(ipv6addr)
         ret = True
      except:
         ret = False
      
      return ret


# -------------------------------------------------------------


class GenerateZoneFile:
   """
   Generate the DNS zonefile (text), from json-encoded zone file
   Use a template to fill in (@template)

   json_data = {
      "$origin": origin server,
      "$ttl":    default time-to-live,
      "soa":     [ soa records ],
      "ns":      [ ns records ],
      "a":       [ a records ],
      "aaaa":    [ aaaa records ]
      "cname":   [ cname records ]
      "mx":      [ mx records ]
      "ptr":     [ ptr records ]
      "txt":     [ txt records ]
      "srv":     [ srv records ]
      "uri":     [ uri records ]
   }
   """
   def __init__(self, zonejson, origin=None, ttl=None, template=None):
      self._zonejson = zonejson
      self._zonefile = ""
      self._json_data = copy.deepcopy(self._zonejson)
      self.__zonedict = json.loads(self._json_data)
      self.__current_origin = ""

      self.logger = logging.getLogger(__name__)
      self.logger.setLevel(logging.DEBUG)
      file_formatter = logging.Formatter('%(asctime)s:%(message)s:')
      file_handler = logging.FileHandler('_zonefile.log')
      file_handler.setLevel(logging.INFO)
      file_handler.setFormatter(file_formatter)
      self.logger.addHandler(file_handler)

      #file_handler.setLevel(logging.ERROR)
      #file_handler.setLevel(logging.INFO)

      if origin is not None:
         self.__zonedict['$origin'] = origin

      if ttl is not None:
         self.__zonedict['$ttl'] = ttl

      if template is None:
         template = DEFAULT_TEMPLATE[:]

      self._zonefile = template
      self._Make_origin()
      self._Make_ttl()
      self._Make_soa()
      self._Make_ns()
      self._Make_a()
      self._Make_aaaa()
      self._Make_cname()
      self._Make_hinfo()
      self._Make_mx()
      self._Make_ptr()
      self._Make_txt()
      self._Make_srv()
      self._Make_uri()

      # remove empty lines
      lines = self._zonefile.split("\n")
      notemptylines = ""
      for line in lines:
         if line.strip() != "":
            notemptylines = notemptylines + line.strip() + "\n"
      self._zonefile = notemptylines + "\n"

   def showtext(self):
      return self._zonefile

   
   def showjson(self):
      return self._zonejson


   def _Make_origin(self):
      """
      Replace {$origin} in template with $ORIGIN record
      """
      record = ""

      try:
         rowdata = self.__zonedict['$origin']
      except:
         rowdata = None

      if rowdata is not None:
         record += "$ORIGIN %s" % rowdata
      else:
         self.logger.warning('$ORIGIN not found! ' + self.__current_origin + ' You have to set $ORIGIN')

      self._zonefile = self._zonefile.replace("{$origin}", record)


   def _Make_ttl(self):
      """
      Replace {$ttl} in template with $TTL record
      """
      record = ""
      
      try:
         rowdata = self.__zonedict['$ttl']
      except:
         rowdata = None

      if rowdata is not None:
         record += "$TTL %s" % rowdata
      else:
         self.logger.warning('$TTL not found! ' + self.__current_origin + ' You have to set $TTL')

      self._zonefile = self._zonefile.replace("{$ttl}", record)


   def _Make_soa(self):
      """
      Replace {SOA} in template with a set of serialized SOA records
      """
      record = self._zonefile[:]
      rowdata = self.__zonedict['soa']

      if len(rowdata) >= 1:
         rowdata = None
         self.logger.warning('Invalid SOA! ' + self.__current_origin + ' Only one SOA is possible.')

      if rowdata is not None:

         rowdata = rowdata[0]

         soadat = []
         domain_fields = ['mname', 'rname']
         param_fields = ['serial', 'refresh', 'retry', 'expire', 'minimum']

         for f in domain_fields + param_fields:
            assert f in list(rowdata.keys()), "Missing '%s' (%s)" % (f, rowdata)

         data_name = str(rowdata.get('name', '@'))
         soadat.append(data_name)

         if rowdata.get('ttl') is not None:
            soadat.append( str(rowdata['ttl']) )

         soadat.append("IN")
         soadat.append("SOA")

         for key in domain_fields:
            value = str(rowdata[key])
            soadat.append(value)

         soadat.append("(")

         for key in param_fields:
            value = str(rowdata[key])
            soadat.append(value)

         soadat.append(")")

         soa_txt = " ".join(soadat)
         record = record.replace("{soa}", soa_txt)

      else:
         # clear all SOA fields
         record = record.replace("{soa}", "")

      self._zonefile = record


   def _Make_ns(self):
      """
      Replace {ns} in template with NS records
      """
      try:
         rowdata = self.__zonedict['ns']
      except:
         rowdata = None
         
      self.__make_rr(rowdata, "NS", "host", "{ns}")


   def _Make_a(self):
      """
      Replace {a} in template with A records
      """
      try:
         rowdata = self.__zonedict['a']
      except:
         rowdata = None
         
      self.__make_rr(rowdata, "A", "ip", "{a}")


   def _Make_aaaa(self):
      """
      Replace {aaaa} in template with AAAA records
      """
      try:
         rowdata = self.__zonedict['aaaa']
      except:
         rowdata = None

      self.__make_rr(rowdata, "AAAA", "ip", "{aaaa}")


   def _Make_cname(self):
      """
      Replace {cname} in template with CNAME records
      """
      try:
         rowdata = self.__zonedict['cname']
      except:
         rowdata = None

      self.__make_rr(rowdata, "CNAME", "alias", "{cname}")


   def _Make_hinfo(self):
      """
      Replace {hinfo} in template with HINFO records
      """
      try:
         rowdata = self.__zonedict['hinfo']
      except:
         rowdata = None

      self.__make_rr(rowdata, "HINFO", ["cpu", "system"], "{hinfo}")


   def _Make_mx(self):
      """
      Replace {mx} in template with MX records
      """
      try:
         rowdata = self.__zonedict['mx']
      except:
         rowdata = None

      self.__make_rr(rowdata, "MX", ["preference", "host"], "{mx}")


   def _Make_ptr(self):
      """
      Replace {ptr} in template with PTR records
      """
      try:
         rowdata = self.__zonedict['ptr']
      except:
         rowdata = None

      self.__make_rr(rowdata, "PTR", "host", "{ptr}")


   def _Make_txt(self):
      """
      Replace {txt} in template with TXT records
      """
      try:
         rowdata = self.__zonedict['txt']
      except:
         rowdata = None
      
      if rowdata is None:
         rowdata_dup = None
      else:
         # quote txt
         rowdata_dup = copy.deepcopy(rowdata)
         for datum in rowdata_dup:
            if isinstance(datum["txt"], list):
               datum["txt"] = " ".join(['"%s"' % entry.replace(";", "\;") for entry in datum["txt"]])
            else:
               datum["txt"] = '"%s"' % datum["txt"].replace(";", "\;")

      self.__make_rr(rowdata_dup, "TXT", "txt", "{txt}")


   def _Make_srv(self):
      """
      Replace {srv} in template with SRV records
      """
      try:
         rowdata = self.__zonedict['srv']
      except:
         rowdata = None

      self.__make_rr(rowdata, "SRV", ["priority", "weight", "port", "target"], "{srv}")


   def _Make_uri(self):
      """
      Replace {uri} in template with URI records
      """
      try:
         rowdata = self.__zonedict['uri']
         rowdata_dup = copy.deepcopy(rowdata)

         for i in range(0, len(rowdata_dup)):
            rowdata_dup[i][field] = '"%s"' % rowdata_dup[i]["target"]
            rowdata_dup[i][field] = rowdata_dup[i]["target"].replace(";", "\;")

      except:
         rowdata = None
         rowdata_dup = None

      self.__make_rr(rowdata_dup, "URI", ["priority", "weight", "target"], "{uri}")


   def __make_rr(self, rowdata, record_type, record_keys, field):
      """
      Meta method:
      Replace $field in template with the serialized $record_type records,
      using @record_key from each datum.
      """
      record = ""

      if rowdata is not None:
         if type(record_keys) == list:
            pass
         elif type(record_keys) == str:
            record_keys = [record_keys]
         else:
            self.logger.warning('Invalid record keys! ' + self.__current_origin)

         for i in range(0, len(rowdata)):
            for record_key in record_keys:
               if record_key not in list(rowdata[i].keys()):
                  self.logger.warning('Missing record key! ' + self.__current_origin + ' ' + record_key)

            record_data = []
            record_data.append( str(rowdata[i].get('name', '@')) )
            if rowdata[i].get('ttl') is not None:
               record_data.append( str(rowdata[i]['ttl']) )

            record_data.append(record_type)
            record_data += [str(rowdata[i][record_key]) for record_key in record_keys]
            if record_data[1] == "HINFO":
               record = record_data[0] + " " 
               record += "\"" + record_data[1] + "\" "
               record += "\"" + record_data[2] + "\" "
               record += "\"" + record_data[3] + "\""
            else:
               record += " ".join(record_data) + "\n"

      self._zonefile = self._zonefile.replace(field, record)


# -------------------------------------------------------------


class InvalidLineException(Exception):
   pass


# -------------------------------------------------------------


class ZonefileLineParser(argparse.ArgumentParser):
   def error(self, message):
      """
      Silent error message
      """
      raise InvalidLineException(message)


# -------------------------------------------------------------

 
class ConvertTime():
   """
   Convert Zonefile Time like 1H into seconds
   Check if between 900 and 2**31 seconds
   """
   def __init__(self):
      self.__minutes = 60
      self.__hour = 3600
      self.__day = 86400

   def convert(self, txt):
      """
      ConvertTime.convert(timestring<str>)
      converts timestring like 1H into seconds

      Return: timestring <str>, error <bool>
      """
      self.__txtvalue = '0' + txt.upper()
      self.__intvalue = 0
      self.__unit = 'S'
      self.__timeerror = False

      try:
         self.__intvalue = int(self.__txtvalue)
      except:
         self.__unit = self.__txtvalue[-1]
         self.__txtvalue = self.__txtvalue[:-1]

         if self.__unit == 'S':
            self.__intvalue = int(self.__txtvalue)
            
         elif self.__unit == 'M':
            self.__intvalue = int(self.__txtvalue) * self.__minutes

         elif self.__unit == 'H':
            self.__intvalue = int(self.__txtvalue) * self.__hour

         elif self.__unit == 'D':
            self.__intvalue = int(self.__txtvalue) * self.__day

         elif self.__unit == 'W':
            self.__intvalue = int(self.__txtvalue) * 7 * self.__day

         else:
            self.__intvalue = 86400
            self.__timeerror = True

      # check range
      if self.__intvalue < 900:
         self.__intvalue = 86400
         self.__timeerror = True

      if self.__intvalue >= 2**31:
         self.__intvalue = 86400
         self.__timeerror = True

      self.__txtvalue = str(self.__intvalue)

      return self.__txtvalue, self.__timeerror



SUPPORTED_RECORDS = [
    '$ORIGIN', '$TTL', 'SOA', 'NS', 'A', 'AAAA', 'CNAME', 'MX', 'PTR', 'TXT', 'SRV', 'URI', 'HINFO',
]
# add CAA, DNSKEY



DEFAULT_TEMPLATE = """
{$origin}\n\
{$ttl}\n\
\n\
{soa}
\n\
{ns}\n\
\n\
{mx}\n\
\n\
{a}\n\
\n\
{aaaa}\n\
\n\
{cname}\n\
\n\
{hinfo}\n\
\n\
{ptr}\n\
\n\
{txt}\n\
\n\
{srv}\n\
\n\
{uri}\n\
"""
