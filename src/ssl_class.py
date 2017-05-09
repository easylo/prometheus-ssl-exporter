from prometheus_client.core import CounterMetricFamily, GaugeMetricFamily , REGISTRY

import json, requests, sys, time, os, ast, signal, datetime

import logging, socket, ssl
                     
class SslCollector(object):

  gauges = {}

  def __init__(self, domains):
        """ initializing attributes"""

        logging.debug('Starting string domains: {0} '.format(domains))
        self.domains = domains.split(',')
        logging.debug('Split of domains: {0} '.format(self.domains))
        self.ssl_port = 443
        self.METRIC_PREFIX = 'ssl_info'
        self.METRIC_DOMAIN = 'domain'
        
  def collect(self):
    
    for domain in self.domains:
      self._collect_metrics(domain)
    
    # Yield all metrics returned
    for gauge_key, gauge in self.gauges.items():
      yield gauge


  def _collect_metrics(self, domain):
    
    logging.info('Starting scan of domain: {0} , port {1}'.format(domain, self.ssl_port))
    self._ssl_certificate_days_valid( ssl_port=self.ssl_port, domain=domain, timeout=60)
    logging.info('Finished scan')

  def _ssl_certificate_days_valid(self, ssl_port, domain, timeout):
      ssl_date_fmt = r'%b %d %H:%M:%S %Y %Z'

      context = ssl.create_default_context()

      # Since we're checking expiry, don't worry about the hostname
      context.check_hostname = False
      conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=domain)
      conn.settimeout(timeout)

      try:
          conn.connect((domain, ssl_port))
          ssl_info = conn.getpeercert()
      # except socket.timeout:
          # continue
      # except ConnectionRefusedError:
          # continue
      except ssl.SSLError as e:
          logging.debug("Couldn't connect to {0} on port {1}, got error {2}".format(domain, ssl_port, e))
          # continue
      # except:
      finally:
          conn.close()

      if len(ssl_info) > 0:
          days_valid = datetime.datetime.strptime(ssl_info['notAfter'], ssl_date_fmt) - datetime.datetime.utcnow()
          not_before = ssl_info['notBefore']
          not_after  = ssl_info['notAfter']
          logging.info("Certificate information received for {0} days valid: {1}".format(domain, days_valid))
          common_name = ssl_info['subject'][-1][0][1]
          serial_number = ssl_info['serialNumber']

          try:
              organization_name = ssl_info['subject'][-2][0][1]
          except :
              organization_name = ''
          
          issuer = ssl_info['issuer'][1][0][1]

          # if not no_dns:
          #     try:
          #         hostname = socket.gethostbyaddr(ip)[0]
          #     except socket.herror:
          #         hostname = ""
          metric_id = ('%s_%s' % (self.METRIC_PREFIX, domain )).lower()
          metric_description = 'Number of days before the certificate expires'
          labels =  ['commonName', 'domain', 'issuer', 'serialNumber','not_before','not_after','organization_name']
          self.gauges[metric_id] = GaugeMetricFamily(metric_id, '%s' % metric_description, value=None, labels=labels)
          self.gauges[metric_id].add_metric([ common_name, domain, issuer, serial_number, not_before, not_after, organization_name], days_valid.days)

      else:
          logging.warning("No certificate information received for {0} on port {1}".format(domain, ssl_port))