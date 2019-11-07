"""Module provider for UnoEuro"""
from __future__ import absolute_import
import json
import logging

import requests
from lexicon.providers.base import Provider as BaseProvider


LOGGER = logging.getLogger(__name__)

NAMESERVER_DOMAINS = ['unoeuro.com']


def provider_parser(subparser):
    """Return the parser for this provider"""
    subparser.add_argument(
        "--auth-accountname", help="specify accountname for authentication")
    subparser.add_argument(
        "--auth-apikey", help="specify apikey for authentication")


class Provider(BaseProvider):
    """Provider class for UnoEuro"""
    def __init__(self, config):
        super(Provider, self).__init__(config)
        self.domain_id = None
        self.api_endpoint = 'https://api.unoeuro.com/1/{ACCOUNTNAME}/{APIKEY}'.format(
            ACCOUNTNAME=self._get_provider_option('auth_accountname'),
            APIKEY=self._get_provider_option('auth_apikey')
        )

    def _authenticate(self):
        # GET /my/products/
        payload = self._get('/my/products/')

        if not payload['products']:
            raise Exception('No domain found')
        for product in payload['products']:
            if product['object'] == self.domain:
                self.domain_id = product['object']
                break
        if not self.domain_id:
            raise Exception("Domain not found")

    def _create_record(self, rtype, name, content):
        # POST /my/products/[object]/dns/records
        data = {
            "type": rtype,
            "name": self._full_name(name),
            "data": content,
        }
        if self._get_lexicon_option('ttl'):
            data['ttl'] = self._get_lexicon_option('ttl')
        if self._get_lexicon_option('priority'):
            data['priority'] = self._get_lexicon_option('priority')

        payload = {'status': 200}
        try:
            path = '/my/products/{domain}/dns/records'.format(domain=self.domain)
            payload = self._post(path, data)
        except requests.exceptions.HTTPError as err:
            pass

        LOGGER.debug('create_record: %s', payload['status'])
        return payload['status'] == 200

    def _list_records(self, rtype=None, name=None, content=None):
        # GET /my/products/[object]/dns/records
        name = name.rstrip('.') if name else name
        path = '/my/products/{domain}/dns/records'.format(domain=self.domain)
        payload = self._get(path)

        records = []
        for record in payload['records']:
            processed_record = {
                'type': record['type'],
                'name': self._full_name(record['name']),
                'ttl': record['ttl'],
                'content': record['data'],
                'id': record['record_id']
            }
            records.append(processed_record)

        if rtype:
            records = [record for record in records if record['type'] == rtype]
        if name:
            records = [
                record for record in records if record['name'] == self._full_name(name)
            ]
        if content:
            records = [
                record for record in records if record['content'] == content]

        LOGGER.debug('list_records: %s', records)
        return records

    def _update_record(self, identifier, rtype=None, name=None, content=None):
        # PUT /my/products/[object]/dns/records/[record_id]
        if identifier is None:
            records = self._list_records(rtype=rtype, name=name)
            if len(records) != 1:
                raise Exception("Did not find exactly one record")
            identifier = records[0]['id']
        data = {
            "type": rtype,
            "name": self._full_name(name),
            "data": content,
        }
        if self._get_lexicon_option('ttl'):
            data['ttl'] = self._get_lexicon_option('ttl')
        if self._get_lexicon_option('priority'):
            data['priority'] = self._get_lexicon_option('priority')

        try:
            path = '/my/products/{domain}/dns/records/{record_id}'.format(
                domain=self.domain,
                record_id=identifier
            )
            payload = self._put(path, data)
        except requests.exceptions.HTTPError as err:
            payload=err.response.json()

        LOGGER.debug('create_record: %s', payload['message'])
        return payload['status'] == 200

    def _delete_record(self, identifier=None, rtype=None, name=None, content=None):
        # DELETE /my/products/[object]/dns/records/[record_id]
        delete_record_id = []
        if not identifier:
            records = self._list_records(rtype, name, content)
            delete_record_id = [record['id'] for record in records]
        else:
            delete_record_id.append(identifier)

        LOGGER.debug('delete_records: %s', delete_record_id)

        for record_id in delete_record_id:
            path = '/my/products/{domain}/dns/records/{record_id}'.format(
                domain=self.domain,
                record_id=record_id
            )
            self._delete(path)

        LOGGER.debug('delete_record: %s', True)
        return True

    # Helpers
    def _request(self, action='GET', url='/', data=None, query_params=None):
        if data is None:
            data = {}
        if query_params is None:
            query_params = {}
        response = requests.request(action, self.api_endpoint + url, params=query_params,
                                    data=json.dumps(data),
                                    headers={
                                        'Content-Type': 'application/json'
                                    })
        # if the request fails for any reason, throw an error.
        response.raise_for_status()
        return response.json()
