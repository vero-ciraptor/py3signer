# pytest_asyncio Investigation Results

## Date: 2026-02-18

## Findings

### Can we replace pytest_asyncio with native pytest async fixtures?

**No.** While modern pytest (7.0+) has improved async support, it still requires `pytest-asyncio` for async fixtures.

### What pytest natively supports

- ✅ Async **test functions** via `@pytest.mark.asyncio` decorator
- ✅ `asyncio_mode = "auto"` configuration option

### What requires pytest-asyncio

- ❌ Async **fixtures** (functions decorated with `@pytest.fixture` that are async)

### Evidence

When running tests without pytest-asyncio installed, pytest emits this warning/error:

```
pytest.PytestRemovedIn9Warning: 'test_example' requested an async fixture 'client', 
with no plugin or hook that handled it. This is usually an error, as pytest does not 
natively support it. This will turn into an error in pytest 9.

See: https://docs.pytest.org/en/stable/deprecations.html#sync-test-depending-on-async-fixture
```

### Current Usage in py3signer

The project has 3 async fixtures that require `@pytest_asyncio.fixture`:

1. `tests/conftest.py::client` - Test client for API tests
2. `tests/conftest.py::client_with_persistence` - Test client with keystore persistence
3. `tests/test_metrics.py::metrics_client` - Test client for metrics server tests

### Why keep pytest_asyncio?

1. **Required for async fixtures** - Native pytest cannot handle async fixtures
2. **Type annotations** - The `# type: ignore[untyped-decorator]` comments are needed because pytest-asyncio's decorators aren't fully typed, but this is a minor inconvenience
3. **Industry standard** - pytest-asyncio is the de facto standard for async testing in Python

### Recommendation

Keep `pytest-asyncio` as a dev dependency. The `# type: ignore[untyped-decorator]` comments are an acceptable trade-off for the functionality provided.

## References

- [pytest-asyncio documentation](https://pytest-asyncio.readthedocs.io/)
- [pytest deprecation notes on async fixtures](https://docs.pytest.org/en/stable/deprecations.html#sync-test-depending-on-async-fixture)
