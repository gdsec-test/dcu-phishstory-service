SUPPORTED_TYPES = ['PHISHING',  # Supported Abuse Ticket Types
                   'MALWARE',
                   'SPAM',
                   'NETWORK_ABUSE',
                   'A_RECORD',
                   'FRAUD_WIRE',
                   'IP_BLOCK',
                   'CONTENT']

SUPPORTED_CLOSURES = ['unresolvable',  # Supported Ticket Close Reasons
                      'unworkable',
                      'resolved',
                      'parked',
                      'false_positive',
                      'suspended',
                      'intentionally_malicious',
                      'shared_ip',
                      'not_hosted',
                      'content_removed',
                      'repeat_offender',
                      'extensive_compromise',
                      'email_sent_to_emea',
                      'transferred',
                      'shopper_compromise',
                      'malware_scanner_notice']

MIDDLEWARE_MODEL = ['ticketId',  # Data model that should be passed to Middleware
                    'type',
                    'source',
                    'sourceDomainOrIp',
                    'sourceSubDomain',
                    'target',
                    'proxy',
                    'reporter']

REPORTER_MODEL = {  # Data that may be returned in a GetTicket request
    'u_number': 'ticketId',
    'u_reporter': 'reporter',
    'u_source': 'source',
    'u_source_domain_or_ip': 'sourceDomainOrIp',
    'u_closed': 'closed',
    'sys_created_on': 'createdAt',
    'u_closed_date': 'closedAt',
    'u_type': 'type',
    'u_target': 'target',
    'u_proxy_ip': 'proxy'}
