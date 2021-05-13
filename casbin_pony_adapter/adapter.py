from typing import Optional

from casbin import load_policy_line
from casbin.persist.adapter_filtered import FilteredAdapter
from pony.orm import Database, Required, PrimaryKey, db_session, select, delete, Optional as PonyOptional

from casbin_pony_adapter import Filter

_adapter = None


class Adapter(FilteredAdapter):
    def __init__(self, db: Database):
        class CasbinRule(db.Entity):
            id = PrimaryKey(int, auto=True)
            ptype = Required(str, max_len=255)
            v0 = PonyOptional(str, max_len=255)
            v1 = PonyOptional(str, max_len=255)
            v2 = PonyOptional(str, max_len=255)
            v3 = PonyOptional(str, max_len=255)
            v4 = PonyOptional(str, max_len=255)
            v5 = PonyOptional(str, max_len=255)

            def __str__(self):
                arr = [self.ptype]
                for v in (self.v0, self.v1, self.v2, self.v3, self.v4, self.v5):
                    if not v:
                        break
                    arr.append(v)
                return ", ".join(arr)

            def __repr__(self):
                return '<CasbinRule {}: "{}">'.format(self.id, str(self))

        self.rule_cls = CasbinRule
        self._filtered = False
        db.generate_mapping(create_tables=True)
        global _adapter
        _adapter = self

    @db_session
    def load_policy(self, model):
        for rule in select(cr for cr in self.rule_cls):
            load_policy_line(str(rule), model)

    @db_session
    def load_filtered_policy(self, model, filter: Filter) -> None:
        results = select(cr for cr in self.rule_cls
                         if (cr.ptype in filter.ptype or not filter.ptype) and
                         (cr.v0 in filter.v0 or not filter.v0) and
                         (cr.v1 in filter.v1 or not filter.v1) and
                         (cr.v2 in filter.v2 or not filter.v2) and
                         (cr.v3 in filter.v3 or not filter.v3) and
                         (cr.v4 in filter.v4 or not filter.v4) and
                         (cr.v5 in filter.v5 or not filter.v5)
                         )
        for rule in results:
            load_policy_line(str(rule), model)
        self._filtered = True

    @db_session
    def save_policy(self, model):
        delete(cr for cr in self.rule_cls)
        for sec in ["p", "g"]:
            if sec not in model.model.keys():
                continue
            for ptype, ast in model.model[sec].items():
                for rule in ast.policy:
                    self._save_policy_line(ptype, rule)

    def add_policy(self, sec, ptype, rule):
        self._save_policy_line(ptype, rule)

    def add_policies(self, sec, ptype, rules):
        for r in rules:
            self.add_policy(sec, ptype, r)

    @db_session
    def remove_policy(self, sec, ptype, rule):
        vs = list(rule)

        def v(i):
            return vs[i] if len(vs) > i else ''

        r = delete(cr for cr in self.rule_cls
                   if cr.ptype == ptype and
                   cr.v0 == v(0) and cr.v1 == v(1) and
                   cr.v0 == v(2) and cr.v1 == v(3) and
                   cr.v0 == v(4) and cr.v1 == v(5)
                   )
        return r > 0

    def remove_policies(self, sec, ptype, rules):
        for r in rules:
            self.remove_policy(sec, ptype, r)

    def remove_filtered_policy(self, sec, ptype, field_index, *field_values):
        """removes policy rules that match the filter from the storage.
        This is part of the Auto-Save feature.
        """
        if not (0 <= field_index <= 5):
            return False
        if not (1 <= field_index + len(field_values) <= 6):
            return False
        rule = [field_values[i-field_index] if i >= field_index else ''
                for i in range(field_index + len(field_values))]
        return self.remove_policy(sec, ptype, rule)

    def is_filtered(self):
        return self._filtered

    @db_session
    def _save_policy_line(self, ptype, rule):
        kwargs = {f'v{i}': v for i, v in enumerate(rule)}
        self.rule_cls(ptype=ptype, **kwargs)


def create_rule(ptype: str, v0: str = '', v1: str = '', v2: str = '', v3: str = '', v4: str = '', v5: str = '',
                adapter: Optional[Adapter] = None):
    adapter = adapter or _adapter
    if adapter is None:
        raise ValueError('No adapter given and none created')

    return adapter.rule_cls(ptype=ptype, v0=v0, v1=v1, v2=v2, v3=v3, v4=v4, v5=v5)
