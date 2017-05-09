from prometheus_client import start_http_server
from prometheus_client.core import REGISTRY

import json, requests, sys, time, os, ast, signal, logging


from ssl_class import SslCollector


def sigterm_handler(_signo, _stack_frame):
  sys.exit(0)

if __name__ == '__main__':
  # Ensure we have something to export
  if not (os.getenv('BIND_PORT') or os.getenv('DOMAINS')):
    print("No BIND_PORT or DOMAINS specified, exiting")
    exit(1)

  start_http_server(int(os.getenv('BIND_PORT')))
  logging.warning('Starting listen on {0} '.format(os.getenv('BIND_PORT')))
  REGISTRY.register(SslCollector(
      os.getenv('DOMAINS')
    )
  )

  signal.signal(signal.SIGTERM, sigterm_handler)
  while True: time.sleep(1)
