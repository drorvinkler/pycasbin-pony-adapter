# Pony ORM Adapter for PyCasbin
SQLAlchemy Adapter is the [Pony ORM](https://www.ponyorm.org) adapter for [PyCasbin](https://github.com/casbin/pycasbin). With this library, Casbin can load a policy from Pony ORM supported databases or save a policy to it.

Based on [Officially Supported Databases](http://www.ponyorm.org/), The current supported databases are:
- PostgreSQL
- MySQL
- SQLite
- Oracle
- CockroachDB

## Installation

```
pip install casbin_pony_adapter
```

## Simple Example

```python
import casbin_pony_adapter
import casbin
from pony.orm import Database

adapter = casbin_pony_adapter.Adapter(Database('sqlite', ':memory:'))

e = casbin.Enforcer('path/to/model.conf', adapter)

sub = "alice"  # the user that wants to access a resource.
obj = "data1"  # the resource that is going to be accessed.
act = "read"  # the operation that the user performs on the resource.

if e.enforce(sub, obj, act):
    # permit alice to read data1casbin_sqlalchemy_adapter
    pass
else:
    # deny the request, show an error
    pass
```


### Getting Help

- [PyCasbin](https://github.com/casbin/pycasbin)

### License

This project is licensed under the [MIT license](LICENSE).
