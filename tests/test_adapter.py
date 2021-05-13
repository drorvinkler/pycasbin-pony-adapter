import os
from unittest import TestCase

import casbin
from pony.orm import Database, db_session

from casbin_pony_adapter import Filter, Adapter, create_rule


@db_session
def data_init():
    create_rule(ptype='p', v0='alice', v1='data1', v2='read')
    create_rule(ptype='p', v0='bob', v1='data2', v2='write')
    create_rule(ptype='p', v0='data2_admin', v1='data2', v2='read')
    create_rule(ptype='p', v0='data2_admin', v1='data2', v2='write')
    create_rule(ptype='g', v0='alice', v1='data2_admin')


def get_fixture(path):
    dir_path = os.path.split(os.path.realpath(__file__))[0] + "/"
    return os.path.abspath(dir_path + path)


def get_enforcer(adapter: casbin.Adapter):
    return casbin.Enforcer(get_fixture('rbac_model.conf'), adapter)


class TestConfig(TestCase):
    def setUp(self):
        db = Database('sqlite', ':memory:')
        self.adapter = Adapter(db)

    def test_enforcer_basic(self):
        data_init()
        e = get_enforcer(self.adapter)
        self.assertTrue(e.enforce('alice', 'data1', 'read'))
        self.assertFalse(e.enforce('bob', 'data1', 'read'))
        self.assertTrue(e.enforce('bob', 'data2', 'write'))
        self.assertTrue(e.enforce('alice', 'data2', 'read'))
        self.assertTrue(e.enforce('alice', 'data2', 'write'))

    def test_add_policy(self):
        e = get_enforcer(self.adapter)

        self.assertFalse(e.enforce('eve', 'data3', 'read'))
        res = e.add_permission_for_user('eve', 'data3', 'read')
        self.assertTrue(res)
        self.assertTrue(e.enforce('eve', 'data3', 'read'))

    def test_add_policies(self):
        e = get_enforcer(self.adapter)

        self.assertFalse(e.enforce('eve', 'data3', 'read'))
        res = e.add_policies((('eve', 'data3', 'read'), ('eve', 'data4', 'read')))
        self.assertTrue(res)
        self.assertTrue(e.enforce('eve', 'data3', 'read'))
        self.assertTrue(e.enforce('eve', 'data4', 'read'))

    def test_save_policy(self):
        model = casbin.Enforcer(get_fixture('rbac_model.conf'), get_fixture('rbac_policy.csv')).model
        self.adapter.save_policy(model)
        e = casbin.Enforcer(get_fixture('rbac_model.conf'), self.adapter)

        self.assertTrue(e.enforce('alice', 'data1', 'read'))
        self.assertFalse(e.enforce('bob', 'data1', 'read'))
        self.assertTrue(e.enforce('bob', 'data2', 'write'))
        self.assertTrue(e.enforce('alice', 'data2', 'read'))
        self.assertTrue(e.enforce('alice', 'data2', 'write'))

    def test_remove_policy(self):
        e = get_enforcer(self.adapter)

        self.assertFalse(e.enforce('alice', 'data5', 'read'))
        e.add_permission_for_user('alice', 'data5', 'read')
        self.assertTrue(e.enforce('alice', 'data5', 'read'))
        e.delete_permission_for_user('alice', 'data5', 'read')
        self.assertFalse(e.enforce('alice', 'data5', 'read'))

    def test_remove_policies(self):
        e = get_enforcer(self.adapter)

        self.assertFalse(e.enforce('alice', 'data5', 'read'))
        self.assertFalse(e.enforce('alice', 'data6', 'read'))
        e.add_policies((('alice', 'data5', 'read'), ('alice', 'data6', 'read')))
        self.assertTrue(e.enforce('alice', 'data5', 'read'))
        self.assertTrue(e.enforce('alice', 'data6', 'read'))
        e.remove_policies((('alice', 'data5', 'read'), ('alice', 'data6', 'read')))
        self.assertFalse(e.enforce('alice', 'data5', 'read'))
        self.assertFalse(e.enforce('alice', 'data6', 'read'))

    def test_remove_filtered_policy(self):
        data_init()
        e = get_enforcer(self.adapter)

        self.assertTrue(e.enforce('alice', 'data1', 'read'))
        e.remove_filtered_policy(1, 'data1')
        self.assertFalse(e.enforce('alice', 'data1', 'read'))

        self.assertTrue(e.enforce('bob', 'data2', 'write'))
        self.assertTrue(e.enforce('alice', 'data2', 'read'))
        self.assertTrue(e.enforce('alice', 'data2', 'write'))

        e.remove_filtered_policy(1, 'data2', 'read')

        self.assertTrue(e.enforce('bob', 'data2', 'write'))
        self.assertFalse(e.enforce('alice', 'data2', 'read'))
        self.assertTrue(e.enforce('alice', 'data2', 'write'))

        e.remove_filtered_policy(2, 'write')

        self.assertFalse(e.enforce('bob', 'data2', 'write'))
        self.assertFalse(e.enforce('alice', 'data2', 'write'))

    def test_filtered_policy(self):
        data_init()
        e = get_enforcer(self.adapter)
        adapter_filter = Filter(ptype=['p'])

        e.load_filtered_policy(adapter_filter)
        self.assertTrue(e.enforce('alice', 'data1', 'read'))
        self.assertFalse(e.enforce('alice', 'data1', 'write'))
        self.assertFalse(e.enforce('alice', 'data2', 'read'))
        self.assertFalse(e.enforce('alice', 'data2', 'write'))
        self.assertFalse(e.enforce('bob', 'data1', 'read'))
        self.assertFalse(e.enforce('bob', 'data1', 'write'))
        self.assertFalse(e.enforce('bob', 'data2', 'read'))
        self.assertTrue(e.enforce('bob', 'data2', 'write'))

        adapter_filter = Filter(v0=['alice'])
        e.load_filtered_policy(adapter_filter)
        self.assertTrue(e.enforce('alice', 'data1', 'read'))
        self.assertFalse(e.enforce('alice', 'data1', 'write'))
        self.assertFalse(e.enforce('alice', 'data2', 'read'))
        self.assertFalse(e.enforce('alice', 'data2', 'write'))
        self.assertFalse(e.enforce('bob', 'data1', 'read'))
        self.assertFalse(e.enforce('bob', 'data1', 'write'))
        self.assertFalse(e.enforce('bob', 'data2', 'read'))
        self.assertFalse(e.enforce('bob', 'data2', 'write'))
        self.assertFalse(e.enforce('data2_admin', 'data2', 'read'))
        self.assertFalse(e.enforce('data2_admin', 'data2', 'write'))

        adapter_filter = Filter(v0=['bob'])
        e.load_filtered_policy(adapter_filter)
        self.assertFalse(e.enforce('alice', 'data1', 'read'))
        self.assertFalse(e.enforce('alice', 'data1', 'write'))
        self.assertFalse(e.enforce('alice', 'data2', 'read'))
        self.assertFalse(e.enforce('alice', 'data2', 'write'))
        self.assertFalse(e.enforce('bob', 'data1', 'read'))
        self.assertFalse(e.enforce('bob', 'data1', 'write'))
        self.assertFalse(e.enforce('bob', 'data2', 'read'))
        self.assertTrue(e.enforce('bob', 'data2', 'write'))
        self.assertFalse(e.enforce('data2_admin', 'data2', 'read'))
        self.assertFalse(e.enforce('data2_admin', 'data2', 'write'))

        adapter_filter = Filter(v0=['data2_admin'])
        e.load_filtered_policy(adapter_filter)
        self.assertTrue(e.enforce('data2_admin', 'data2', 'read'))
        self.assertTrue(e.enforce('data2_admin', 'data2', 'read'))
        self.assertFalse(e.enforce('alice', 'data1', 'read'))
        self.assertFalse(e.enforce('alice', 'data1', 'write'))
        self.assertFalse(e.enforce('alice', 'data2', 'read'))
        self.assertFalse(e.enforce('alice', 'data2', 'write'))
        self.assertFalse(e.enforce('bob', 'data1', 'read'))
        self.assertFalse(e.enforce('bob', 'data1', 'write'))
        self.assertFalse(e.enforce('bob', 'data2', 'read'))
        self.assertFalse(e.enforce('bob', 'data2', 'write'))

        adapter_filter = Filter(v0=['alice', 'bob'])
        e.load_filtered_policy(adapter_filter)
        self.assertTrue(e.enforce('alice', 'data1', 'read'))
        self.assertFalse(e.enforce('alice', 'data1', 'write'))
        self.assertFalse(e.enforce('alice', 'data2', 'read'))
        self.assertFalse(e.enforce('alice', 'data2', 'write'))
        self.assertFalse(e.enforce('bob', 'data1', 'read'))
        self.assertFalse(e.enforce('bob', 'data1', 'write'))
        self.assertFalse(e.enforce('bob', 'data2', 'read'))
        self.assertTrue(e.enforce('bob', 'data2', 'write'))
        self.assertFalse(e.enforce('data2_admin', 'data2', 'read'))
        self.assertFalse(e.enforce('data2_admin', 'data2', 'write'))

        adapter_filter = Filter(v0=['alice', 'bob'], v1=['data1'])
        e.load_filtered_policy(adapter_filter)
        self.assertTrue(e.enforce('alice', 'data1', 'read'))
        self.assertFalse(e.enforce('alice', 'data1', 'write'))
        self.assertFalse(e.enforce('alice', 'data2', 'read'))
        self.assertFalse(e.enforce('alice', 'data2', 'write'))
        self.assertFalse(e.enforce('bob', 'data1', 'read'))
        self.assertFalse(e.enforce('bob', 'data1', 'write'))
        self.assertFalse(e.enforce('bob', 'data2', 'read'))
        self.assertFalse(e.enforce('bob', 'data2', 'write'))
        self.assertFalse(e.enforce('data2_admin', 'data2', 'read'))
        self.assertFalse(e.enforce('data2_admin', 'data2', 'write'))

        adapter_filter = Filter(v1=['data1'])
        e.load_filtered_policy(adapter_filter)
        self.assertTrue(e.enforce('alice', 'data1', 'read'))
        self.assertFalse(e.enforce('alice', 'data1', 'write'))
        self.assertFalse(e.enforce('alice', 'data2', 'read'))
        self.assertFalse(e.enforce('alice', 'data2', 'write'))
        self.assertFalse(e.enforce('bob', 'data1', 'read'))
        self.assertFalse(e.enforce('bob', 'data1', 'write'))
        self.assertFalse(e.enforce('bob', 'data2', 'read'))
        self.assertFalse(e.enforce('bob', 'data2', 'write'))
        self.assertFalse(e.enforce('data2_admin', 'data2', 'read'))
        self.assertFalse(e.enforce('data2_admin', 'data2', 'write'))

        adapter_filter = Filter(v1=['data2'])
        e.load_filtered_policy(adapter_filter)
        self.assertFalse(e.enforce('alice', 'data1', 'read'))
        self.assertFalse(e.enforce('alice', 'data1', 'write'))
        self.assertFalse(e.enforce('alice', 'data2', 'read'))
        self.assertFalse(e.enforce('alice', 'data2', 'write'))
        self.assertFalse(e.enforce('bob', 'data1', 'read'))
        self.assertFalse(e.enforce('bob', 'data1', 'write'))
        self.assertFalse(e.enforce('bob', 'data2', 'read'))
        self.assertTrue(e.enforce('bob', 'data2', 'write'))
        self.assertTrue(e.enforce('data2_admin', 'data2', 'read'))
        self.assertTrue(e.enforce('data2_admin', 'data2', 'write'))

        adapter_filter = Filter(v2=['read'])
        e.load_filtered_policy(adapter_filter)
        self.assertTrue(e.enforce('alice', 'data1', 'read'))
        self.assertFalse(e.enforce('alice', 'data1', 'write'))
        self.assertFalse(e.enforce('alice', 'data2', 'read'))
        self.assertFalse(e.enforce('alice', 'data2', 'write'))
        self.assertFalse(e.enforce('bob', 'data1', 'read'))
        self.assertFalse(e.enforce('bob', 'data1', 'write'))
        self.assertFalse(e.enforce('bob', 'data2', 'read'))
        self.assertFalse(e.enforce('bob', 'data2', 'write'))
        self.assertTrue(e.enforce('data2_admin', 'data2', 'read'))
        self.assertFalse(e.enforce('data2_admin', 'data2', 'write'))

        adapter_filter = Filter(v2=['write'])
        e.load_filtered_policy(adapter_filter)
        self.assertFalse(e.enforce('alice', 'data1', 'read'))
        self.assertFalse(e.enforce('alice', 'data1', 'write'))
        self.assertFalse(e.enforce('alice', 'data2', 'read'))
        self.assertFalse(e.enforce('alice', 'data2', 'write'))
        self.assertFalse(e.enforce('bob', 'data1', 'read'))
        self.assertFalse(e.enforce('bob', 'data1', 'write'))
        self.assertFalse(e.enforce('bob', 'data2', 'read'))
        self.assertTrue(e.enforce('bob', 'data2', 'write'))
        self.assertFalse(e.enforce('data2_admin', 'data2', 'read'))
        self.assertTrue(e.enforce('data2_admin', 'data2', 'write'))
