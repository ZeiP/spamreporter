from email.parser import Parser
import email
import smtplib
import requests, re, os
import quopri
import time
from chardet.universaldetector import UniversalDetector
import subprocess
import config

class SpamReporter:
  def __init__(self, dir):
    self.messages = {}
    self.errors = []
    for filename in os.listdir(dir):
      filename = dir + '/' + filename
      if os.path.isfile(filename):
        print('Parsing ' + filename)
        self.messages[filename] = self.do_file(filename)

  def deliver_to_spamcop(self, filename):
    print('---------------')
    print('Handling ' + filename)
    print()
    msg = self.messages[filename]['msg']
    ip = self.messages[filename]['ip']

    sc_auth = (config.SPAMCOP_USERNAME, config.SPAMCOP_PASSWORD)

    data = {'action': 'submit', 'spam': str(msg), 'x1': 'Process Spam', 'verbose': 1}
    r = requests.post('https://members.spamcop.net/sc', data=data, auth=sc_auth)

    res = str(r.text)

    while "Please wait - subscribe to remove this delay" in res:
      url = r.url
      print('Waiting for 6 seconds to pass the delay')
      time.sleep(6)
      r = requests.get(url, auth=sc_auth)
      res = str(r.text)

    result = re.findall('<div class="error">(.*?)<\/div>', res, re.DOTALL)
    error = False
    error_messages = []
    for row in result:
      error_messages.append(row)
      print('ERROR: ' + row)
      error = True
    if error:
      self.errors.append({'errors': error_messages, 'filename': filename})

    if 'name="sendreport"' not in res:
      if error:
        for error_message in error_messages:
          if 'too old to file a spam report' in error_message or 'ISP has indicated spam will cease' in error_message:
            print('Manual reporting not required, removing.')
            os.remove(filename)
      else:
        print(res)
      print('No send form.')
      return False

    result = re.findall('<input type="([a-z]+)" name="([a-z0-9]+)"(\s+value="([^"]+)"| (checked))?>', res, re.DOTALL)

    # Rebuild the input fields as a POST data dictionary
    data = {}
    for row in result:
      if row[0] == 'checkbox':
        if row[4] == 'checked':
          data[row[1]] = 'on'
      elif row[0] != 'submit':
        if row[3]:
          data[row[1]] = row[3]

    # Used to check that we have at least one useful reporting address based on the source IP, otherwise
    # don't remove the spam but instead handle this later manually.
    valid_source_address = False
    masters = []
    for i in range(1, int(data['max'])):
      typename = 'type' + str(i)
      if data[typename] and (data[typename] == 'source' or data[typename] == 'bounce' or data[typename] == 'i-source' or data[typename] == 'i-bounce'):
        mastername = 'master' + str(i)
        masters.append(data[mastername])
        if 'devnull.spamcop.net' not in data[mastername] and '@' in data[mastername]:
          valid_source_address = True
          break

    if not valid_source_address:
      print('There isn\'t a useful source abuse address for this IP')
      self.errors.append({'errors': 'No useful source abuse address in ' + str(masters), 'filename': filename})

    # Additional confirmation for the development phase, this should later be removed.
    for i in range(1, int(data['max'])):
      print(data['type' + str(i)] + ' (' + data['info' + str(i)] + '): ' + data['master' + str(i)])

    # Check that the source IP detected by SpamCop is the same as the one we deduced.
    if data['source'] != ip:
      print("\n".join(self.messages[filename]['received']))
      print('The detected IP doesn\'t match the one SpamCop found. Ours: ' + ip + ', SpamCop\'s: ' + data['source'])
      if not self.get_confirmation('Is the SpamCop IP correct anyway?'):
        print('Bailing out.')
        return False

    if config.WAIT_SC_REPORT:
      print('Waiting for 5 seconds')
      time.sleep(5)

    if config.CONFIRM_SC_REPORT and not self.get_confirmation('Confirmation: Is this ok?'):
      print('Bailing out.')
      return False

    r = requests.post('https://members.spamcop.net/sc', data=data, auth=sc_auth)
    if 'sent to' in str(r.text):
      # If we didn't have a valid source abuse address, report false even though the reporting
      # itself went ok; it still require manual reporting.
      if valid_source_address:
        os.remove(filename)
      return valid_source_address
    else:
      print('Seems the report wasn\'t sent, wonder why?')
      print(r.text)
      return False

  def do_file(self, filename):
    data = {}

    detector = UniversalDetector()
    detector.reset()
    with open(filename, 'rb') as f:
      for row in f:
        detector.feed(row)
        if detector.done:
          break
    detector.close()
    charset = detector.result['encoding']
    data['charset'] = charset

    with open(filename, encoding=charset) as fp:
      msg = Parser().parse(fp)
      received = msg.get_all('received')
      for r in received:
        if re.search(config.LOCAL_DELIVERED_REGEXP, r):
          own = r
        else:
          break
      # Parse the last own received line to get the perpetrator's IP
      res = re.search('from .*?\[(IPv6\:)?([A-Za-z0-9\.\:]+)\]', own)
      data['received'] = received
      data['ip'] = res.groups()[1]
      data['last_received'] = own
#      data['subject'] = quopri.decodestring(msg.get('subject'), True)
      data['subject'] = msg.get('subject')

      # Truncate the payload to save bandwidth and quota.
#      print(msg.get_payload())
#      payload = msg.get_payload()[:4000] + "\n[TRUNCATED TO 4000 BYTES]"
#      msg.set_payload(payload)
      data['msg'] = msg
      return data

  def ask_confirmation(self):
    for filename, spam in self.messages.items():
      print()
      print(spam["subject"])
      print(spam["ip"])
      print(spam["last_received"])
      if not self.get_confirmation('Is this ok?'):
        print('Bailing out.')
        exit()

  def send_reports(self):
    for filename, spam in self.messages.items():
      self.deliver_to_spamcop(filename)

  def get_confirmation(self, prompt):
    while True:
      c = input(prompt).lower()
      if c == 'y' or c == 'yes':
        return True
      elif c == 'n' or c == 'no':
        return False

  def send_custom_report(self, filename):
    msg = self.messages[filename]['msg']
    ip = self.messages[filename]['ip']

    print('---------------')
    print(filename)
    print("Proposing IP: " + self.messages[filename]['ip'])
    print(subprocess.run(["whois", self.messages[filename]['ip']]))
    print("\n".join(self.messages[filename]['received']))
    print(self.messages[filename]['subject'])
    to = input('Which address to send the report (separate multiple with comma)? ')
    if '@' not in to:
      return False

    print(config.CUSTOM_REPORT_TEXTS)
    addt = input('Which additional text do you want attached?')

    report = email.message.Message()
    report['From'] = config.CUSTOM_REPORT_FROM
    report['Subject'] = "Spam report"
    report.add_header('Content-Type', 'text/plain')
    message = "Reporting spam from " + ip + ". The actual message is below."
    if addt and config.CUSTOM_REPORT_TEXTS[addt]:
      message = message + "\n\n" + config.CUSTOM_REPORT_TEXTS[addt]
    message = message + "\n\n[ Offending message ]\n" + str(msg)
    report.set_payload(message, self.messages[filename]['charset'])
    smtp_obj = smtplib.SMTP(config.SMTP_SERVER)

    for address in to.split(','):
      address = address.strip()
      if report['To']:
        report.replace_header('To', address)
      else:
        report['To'] = address
      smtp_obj.sendmail(report['From'], [report['To'], config.CUSTOM_REPORT_BCC], report.as_string())

    smtp_obj.quit()
    os.remove(filename)
    print()
    return True

  def send_custom_reports(self):
    for filename, spam in self.messages.items():
      if os.path.isfile(filename):
        self.send_custom_report(filename)

reporter = SpamReporter(config.SPAM_MAILDIR_PATH)
reporter.ask_confirmation()
reporter.send_reports()
print()
print()
print('Errors for the run:')
for row in reporter.errors:
  print(row['filename'])
  print(row['errors'])
print('End of errors.')
print()
reporter.send_custom_reports()
