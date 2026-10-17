import os

# Hermetic by default: never write an audit log from the tests.
os.environ["WIN11USB_DISABLE_AUDIT_LOG"] = "1"
