import json

import mongomock
from mock import MagicMock, patch
from nose.tools import (assert_equal, assert_false, assert_is_none,
                        assert_raises, assert_true)
from requests import codes

from service.api.snow_api import SNOWAPI, SNOWHelper
from settings import TestAppConfig


class TestSNOWAPI:

    @classmethod
    def setup(cls):
        cls._api = SNOWAPI(TestAppConfig(), None)
        cls._api._db._mongo._collection = mongomock.MongoClient().db.collection
        cls._api._emaildb._mongo._collection = mongomock.MongoClient().db.collection
        cls._api._db._mongo.add_incident(dict(_id=1234, type='PHISHING', reporter='111222333',
                                              sourceDomainOrIp='abc.com', phishstory_status='OPEN',
                                              sourceSubDomain='www.abc.com', source='http://www.abc.com'))
        cls._api._db._mongo.add_incident(dict(_id=1235, type='PHISHING', reporter='111222333',
                                              sourceDomainOrIp='abc.com', phishstory_status='PAUSED',
                                              sourceSubDomain='abc.com', source='http://abc.com'))
        cls._api._db._mongo.add_incident(dict(_id=1236, type='PHISHING', reporter='111222333',
                                              sourceDomainOrIp='abc.com', phishstory_status='PROCESSING',
                                              sourceSubDomain='abc.com', source='http://abc.com'))
        cls._api._db._mongo.add_incident(dict(_id=1237, type='PHISHING', reporter='111222333',
                                              sourceDomainOrIp='abc.com', phishstory_status='OPEN',
                                              sourceSubDomain='www.abc.com', source='http://www.abc.com'))
        cls._api._db._mongo.add_incident(dict(_id=1238, type='PHISHING', reporter='111222333',
                                              sourceDomainOrIp='abc.com', phishstory_status='OPEN',
                                              sourceSubDomain='www.abc.com', source='http://www.abc.com'))
        db_downtime = TestAppConfig()
        db_downtime.DATABASE_IMPACTED = True
        cls._api_downtime = SNOWAPI(db_downtime, None)

    # _check_duplicate tests
    def test_check_duplicate_none(self):
        assert_raises(Exception, self._api.check_duplicate, None)

    @patch.object(SNOWHelper, 'get_request')
    def test_check_duplicate_true(self, get_request):
        get_request.return_value = MagicMock(content=json.dumps({'result': [{'u_number': 'test-ticket'}]}))
        assert_true(self._api.check_duplicate('test-source'))

    @patch.object(SNOWHelper, 'get_request', return_value=MagicMock(content=json.dumps({'result': []})))
    def test_check_duplicate_false(self, get_request):
        assert_false(self._api.check_duplicate('test-source'))

    @patch.object(SNOWHelper, 'get_request')
    def test_check_duplicate_exclude(self, get_request):
        get_request.return_value = MagicMock(content=json.dumps({'result': [{'u_number': 'test-ticket'}]}))
        assert_false(self._api.check_duplicate('test-source', 'test-ticket'))

    @patch.object(SNOWHelper, 'get_request', side_effect=Exception())
    def test_check_duplicate_exception(self, get_request):
        get_request.return_value = MagicMock(content=json.dumps({}))
        assert_raises(Exception, self._api.check_duplicate, 'test-source')

    # create_ticket tests
    def test_create_ticket_no_source(self):
        assert_raises(Exception, self._api.create_ticket, {})

    @patch.object(SNOWAPI, 'check_duplicate', return_value=True)
    def test_create_ticket_duplicate(self, check_duplicate):
        assert_raises(Exception, self._api.create_ticket, {'source': 'test-source', 'type': 'SPAM'})

    @patch.object(SNOWAPI, 'check_duplicate', return_value=False)
    @patch.object(SNOWHelper, 'post_request', return_value=None, side_effect=Exception())
    def test_create_ticket_exception(self, post_request, check_duplicate):
        assert_raises(Exception, self._api.create_ticket, {'source': 'test-source', 'type': 'SPAM'})

    @patch.object(SNOWAPI, 'check_duplicate', return_value=False)
    @patch.object(SNOWHelper, 'post_request')
    def test_create_ticket_status_code(self, post_request, check_duplicate):
        post_request.return_value = MagicMock(status_code=codes.not_found, content=json.dumps({}))
        assert_raises(Exception, self._api.create_ticket, {'source': 'test-source', 'type': 'SPAM'})

    @patch.object(SNOWAPI, '_send_to_middleware', return_value=None)
    @patch.object(SNOWHelper, 'post_request')
    @patch.object(SNOWAPI, 'check_duplicate', return_value=False)
    def test_create_ticket(self, check_duplicate, post_request, _send_to_middleware):
        post_request.return_value = MagicMock(status_code=codes.created,
                                              content=json.dumps({'result': {'u_number': 'test-ticket'}}))

        data = {'type': 'PHISHING', 'metadata': {'test': 'test'}, 'source': 'test-source',
                'sourceDomainOrIp': '', 'sourceSubDomain': '', 'proxy': '', 'reporter': '', 'target': ''}
        assert_equal(self._api.create_ticket(data), 'test-ticket')

    @patch.object(SNOWAPI, '_send_to_middleware', return_value=None)
    @patch.object(SNOWHelper, 'post_request')
    @patch.object(SNOWAPI, '_domain_cap_reached', return_value=None)
    @patch.object(SNOWAPI, 'check_duplicate', return_value=False)
    def test_create_ticket_db_downtime(self, check_duplicate, _domain_cap_reached, post_request, _send_to_middleware):
        post_request.return_value = MagicMock(status_code=codes.created,
                                              content=json.dumps({'result': {'u_number': 'test-ticket'}}))

        data = {'type': 'PHISHING', 'metadata': {'test': 'test'}, 'source': 'test-source',
                'sourceDomainOrIp': '', 'sourceSubDomain': '', 'proxy': '', 'reporter': '', 'target': ''}
        assert_equal(self._api_downtime.create_ticket(data), 'test-ticket')
        _send_to_middleware.assert_not_called()
        _domain_cap_reached.assert_not_called()

    @patch.object(SNOWAPI, '_send_to_middleware', return_value=None)
    @patch.object(SNOWHelper, 'post_request')
    @patch.object(SNOWAPI, 'check_duplicate', return_value=False)
    def test_create_ticket_with_reporter_email(self, check_duplicate, post_request, _send_to_middleware):
        post_request.return_value = MagicMock(status_code=codes.created,
                                              content=json.dumps({'result': {'u_number': 'test-ticket'}}))

        data = {'type': 'PHISHING', 'metadata': {'test': 'test'}, 'source': 'test-source', 'sourceDomainOrIp': '',
                'sourceSubDomain': '', 'proxy': '', 'reporter': '', 'target': '', 'reporterEmail': 'test@test.com'}
        assert_equal(self._api.create_ticket(data), 'test-ticket')

    # update_ticket tests
    def test_update_ticket_no_close_reason(self):
        assert_raises(Exception, self._api.update_ticket, {'closed': True})

    @patch.object(SNOWAPI, '_get_sys_id')
    def test_update_ticket_no_sys_id(self, _get_sys_id):
        _get_sys_id.return_value = None
        assert_raises(Exception, self._api.update_ticket, {})

    @patch.object(SNOWAPI, '_get_sys_id')
    @patch.object(SNOWHelper, 'patch_request')
    def test_update_patch_exception(self, patch_request, _get_sys_id):
        patch_request.side_effect = Exception()
        patch_request.return_value = None
        _get_sys_id.return_value = 'test-sys-id'
        assert_raises(Exception, self._api.update_ticket, {})

    @patch.object(SNOWAPI, '_get_sys_id')
    @patch.object(SNOWHelper, 'patch_request')
    def test_update_patch_status_code(self, patch_request, _get_sys_id):
        patch_request.return_value = MagicMock(status_code=codes.not_found, content=json.dumps({}))
        _get_sys_id.return_value = 'test-sys-id'
        assert_raises(Exception, self._api.update_ticket, {})

    @patch.object(SNOWAPI, '_get_sys_id')
    @patch.object(SNOWHelper, 'patch_request')
    def test_update_ticket(self, patch_request, _get_sys_id):
        patch_request.return_value = MagicMock(status_code=codes.ok, content=json.dumps({}))
        _get_sys_id.return_value = 'test-sys-id'
        assert_is_none(self._api.update_ticket({'ticketId': 'test-ticket', 'closed': True, 'close_reason': 'false_positive'}))

    def test_update_ticket_db_downtime(self):
        assert_raises(Exception, self._api.update_ticket)

    # get_tickets tests
    @patch.object(SNOWHelper, 'get_request')
    def test_get_tickets_get_exception(self, get_request):
        get_request.side_effect = Exception()
        get_request.return_value = None
        assert_raises(Exception, self._api.get_tickets, {})

    @patch.object(SNOWHelper, 'get_request')
    def test_get_tickets_get_status_code(self, get_request):
        get_request.return_value = MagicMock(status_code=codes.not_found, content=json.dumps({}))
        assert_raises(Exception, self._api.get_tickets, {})

    @patch.object(SNOWHelper, 'get_request')
    def test_get_tickets_get_no_result(self, get_request):
        get_request.return_value = MagicMock(status_code=codes.ok, content=json.dumps({}))
        assert_raises(Exception, self._api.get_tickets, {})

    @patch.object(SNOWHelper, 'get_request')
    def test_get_tickets(self, get_request):
        get_request.return_value = MagicMock(status_code=codes.ok,
                                             content=json.dumps({'result': [{'u_number': '1'}, {'u_number': '2'}]}))
        assert_equal(self._api.get_tickets({}), {'ticketIds': ['1', '2']})

    @patch.object(SNOWHelper, 'get_request')
    def test_get_tickets_pagination(self, get_request):

        get_request.return_value = MagicMock(status_code=codes.ok,
                                             headers=MagicMock(_store={'x-total-count': ('X-Total-Count', '2')}),
                                             content=json.dumps({'result': [{'u_number': '1'}, {'u_number': '2'}]}))
        pagination = {'firstOffset': 0, 'total': 2, 'limit': 10, 'lastOffset': 2}
        assert_equal(self._api.get_tickets({'offset': 0, 'limit': 10}), {'ticketIds': ['1', '2'], 'pagination': pagination})

    # get_ticket_info tests
    @patch.object(SNOWHelper, 'get_request')
    def test_get_ticket_info_get_exception(self, get_request):
        get_request.side_effect = Exception()
        get_request.return_value = None
        assert_raises(Exception, self._api.get_ticket, {})

    @patch.object(SNOWHelper, 'get_request')
    def test_get_ticket_info_status_code(self, get_request):
        get_request.return_value = MagicMock(status_code=codes.not_found, content=json.dumps({}))
        assert_raises(Exception, self._api.get_ticket, {})

    @patch.object(SNOWHelper, 'get_request')
    def test_get_ticket_info_no_result(self, get_request):
        get_request.return_value = MagicMock(status_code=codes.ok, content=json.dumps({}))
        assert_raises(Exception, self._api.get_ticket, {})

    @patch.object(SNOWHelper, 'get_request')
    def test_get_ticket_info(self, get_request):
        payload = {'result': [{'u_number': '1', 'u_closed': 'true', 'u_target': '', 'u_reporter': '', 'u_source': '',
                               'u_source_domain_or_ip': '', 'sys_created_on': '', 'u_closed_date': '',
                               'u_type': 'PHISHING', 'u_proxy_ip': ''}]}
        expected = {'ticketId': '1', 'closed': True, 'target': '', 'reporter': '', 'source': '', 'sourceDomainOrIp': '',
                    'createdAt': '', 'closedAt': '', 'type': 'PHISHING', 'proxy': ''}
        get_request.return_value = MagicMock(status_code=codes.ok, content=json.dumps(payload))
        assert_equal(self._api.get_ticket({'ticketId': '1'}), expected)

    # _get_sys_id tests
    @patch.object(SNOWHelper, 'get_request')
    def test_get_sys_id_get_exception(self, get_request):
        get_request.side_effect = Exception()
        assert_is_none(self._api._get_sys_id('test-id'))

    @patch.object(SNOWHelper, 'get_request')
    def test_get_sys_id_bad_status_code(self, get_request):
        get_request.return_value = MagicMock(status_code=codes.not_found, content=json.dumps({}))
        assert_raises(Exception, self._api._get_sys_id('test-id'))

    @patch.object(SNOWHelper, 'get_request')
    def test_get_sys_id_no_result(self, get_request):
        get_request.return_value = MagicMock(status_code=codes.ok, content=json.dumps({}))
        assert_is_none(self._api._get_sys_id('test-id'))

    @patch.object(SNOWHelper, 'get_request')
    def test_get_sys_id_empty_result(self, get_request):
        get_request.return_value = MagicMock(status_code=codes.ok, content=json.dumps({'result': []}))
        assert_is_none(self._api._get_sys_id('test-id'))

    @patch.object(SNOWHelper, 'get_request')
    def test_get_sys_id(self, get_request):
        get_request.return_value = MagicMock(status_code=codes.ok, content=json.dumps({'result': [{'sys_id': '1'}]}))
        assert_equal(self._api._get_sys_id('test-id'), '1')

    @patch.object(SNOWAPI, '_send_to_middleware', return_value=None)
    @patch.object(SNOWHelper, 'post_request')
    @patch.object(SNOWAPI, 'check_duplicate', return_value=False)
    def test_create_ticket_iris_evidence(self, check_duplicate, post_request, _send_to_middleware):
        post_request.return_value = MagicMock(status_code=codes.created,
                                              content=json.dumps({'result': {'u_number': 'test-ticket-iris'}}))

        data = {'type': 'PHISHING', 'metadata': {'test': 'test'}, 'source': 'test-source', 'sourceDomainOrIp': '', 'sourceSubDomain': '',
                'proxy': '', 'reporter': '', 'target': '', 'info': 'IRIS'}

        self._api.create_ticket(data)
        mongo_obj = self._api._db.get_incident('test-ticket-iris')
        assert_true(mongo_obj.get('evidence', {}).get('iris'))
        assert_false(mongo_obj.get('evidence', {}).get('snow'))

    @patch.object(SNOWAPI, '_send_to_middleware', return_value=None)
    @patch.object(SNOWHelper, 'post_request')
    @patch.object(SNOWAPI, 'check_duplicate', return_value=False)
    def test_create_ticket_snow_evidence(self, check_duplicate, post_request, _send_to_middleware):
        post_request.return_value = MagicMock(status_code=codes.created,
                                              content=json.dumps({'result': {'u_number': 'test-ticket-snow'}}))

        data = {'type': 'PHISHING', 'metadata': {'test': 'test'}, 'source': 'test-source', 'sourceDomainOrIp': '', 'sourceSubDomain': '',
                'proxy': '', 'reporter': '', 'target': '', 'info': 'EMAIL HEADERS: Header Info - EMAIL CONTENT: Body'}

        self._api.create_ticket(data)
        mongo_obj = self._api._db.get_incident('test-ticket-snow')
        assert_true(mongo_obj.get('evidence', {}).get('snow'))
        assert_false(mongo_obj.get('evidence', {}).get('iris'))

    @patch.object(SNOWAPI, 'check_duplicate', return_value=False)
    def test_domain_cap_reached(self, get_request):
        data = dict(type='PHISHING', reporter='111222333', sourceDomainOrIp='abc.com',
                    phishstory_status='OPEN', sourceSubDomain='www.abc.com', source='http://www.abc.com')
        assert_raises(Exception, self._api.create_ticket, data)

    @patch.object(SNOWAPI, '_send_to_middleware', return_value=None)
    @patch.object(SNOWHelper, 'post_request')
    @patch.object(SNOWAPI, 'check_duplicate', return_value=False)
    def test_domain_cap_reached_content(self, check_duplicate, post_request, _send_to_middleware):
        post_request.return_value = MagicMock(status_code=codes.created,
                                              content=json.dumps({'result': {'u_number': 'test-ticket'}}))

        data = {'type': 'CONTENT', 'metadata': {'test': 'test'}, 'source': 'test-source', 'sourceDomainOrIp': '',
                'sourceSubDomain': '', 'proxy': '', 'reporter': '', 'target': '',
                'info': 'EMAIL HEADERS: Header Info - EMAIL CONTENT: Body'}
        assert_equal(self._api.create_ticket(data), 'test-ticket')

    @patch.object(SNOWAPI, '_send_to_middleware', return_value=None)
    @patch.object(SNOWHelper, 'post_request')
    @patch.object(SNOWAPI, 'check_duplicate', return_value=False)
    def test_domain_cap_reached_usergen(self, check_duplicate, post_request, _send_to_middleware):
        post_request.return_value = MagicMock(status_code=codes.created,
                                              content=json.dumps({'result': {'u_number': 'test-ticket'}}))

        data = {'type': 'PHISHING', 'metadata': {'test': 'test'}, 'source': 'test-source',
                'sourceDomainOrIp': 'wix.com', 'sourceSubDomain': '', 'proxy': '', 'reporter': '', 'target': '',
                'info': 'EMAIL HEADERS: Header Info - EMAIL CONTENT: Body'}
        assert_equal(self._api.create_ticket(data), 'test-ticket')

    @patch.object(SNOWAPI, '_send_to_middleware', return_value=None)
    @patch.object(SNOWHelper, 'post_request')
    @patch.object(SNOWAPI, 'check_duplicate', return_value=False)
    def test_domain_cap_reached_sucuri(self, check_duplicate, post_request, _send_to_middleware):
        post_request.return_value = MagicMock(status_code=codes.created,
                                              content=json.dumps({'result': {'u_number': 'test-ticket'}}))

        data = {'type': 'PHISHING', 'metadata': {'test': 'test'}, 'source': 'test-source',
                'sourceDomainOrIp': '', 'sourceSubDomain': '', 'proxy': '', 'reporter': '198103515', 'target': '',
                'info': 'EMAIL HEADERS: Header Info - EMAIL CONTENT: Body'}
        assert_equal(self._api.create_ticket(data), 'test-ticket')

    @patch.object(SNOWAPI, '_send_to_middleware', return_value=None)
    @patch.object(SNOWHelper, 'post_request')
    @patch.object(SNOWAPI, 'check_duplicate', return_value=False)
    def test_domain_cap_reached_diff_subdomain(self, check_duplicate, post_request, _send_to_middleware):
        post_request.return_value = MagicMock(status_code=codes.created,
                                              content=json.dumps({'result': {'u_number': 'test-ticket'}}))

        data = dict(type='PHISHING', reporter='111222333', sourceDomainOrIp='abc.com',
                    phishstory_status='OPEN', sourceSubDomain='docs.abc.com', source='http://docs.abc.com',
                    metadata={}, proxy='', target='')
        assert_equal(self._api.create_ticket(data), 'test-ticket')

    @patch.object(SNOWAPI, '_send_to_middleware', return_value=None)
    @patch.object(SNOWHelper, 'post_request')
    @patch.object(SNOWAPI, 'check_duplicate', return_value=False)
    def test_domain_cap_reached_missing_domain(self, check_duplicate, post_request, _send_to_middleware):
        post_request.return_value = MagicMock(status_code=codes.created,
                                              content=json.dumps({'result': {'u_number': 'test-ticket'}}))

        data = {'type': 'PHISHING', 'metadata': {'test': 'test'}, 'source': 'test-source',
                'sourceDomainOrIp': '', 'sourceSubDomain': '', 'proxy': '', 'reporter': '', 'target': '',
                'info': 'EMAIL HEADERS: Header Info - EMAIL CONTENT: Body'}
        assert_equal(self._api.create_ticket(data), 'test-ticket')
