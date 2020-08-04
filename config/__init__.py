CUSTOM_REPORT_TEXTS={
  "f": "The spam is caused by a defective feedback form, which sends the form content also to the counterfeit sender that the spammer has entered. Please add a CAPTCHA check or disable the form / sending the form content to the entered email address to fix the issue.",
}

SMTP_SERVER='localhost'

WAIT_SC_REPORT=False
CONFIRM_SC_REPORT=False

try:
  from config.local import *
except ImportError:
  pass
