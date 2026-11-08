import importlib
_CACHE: dict[str, object] = {}

def get(uses: str):
    """Map a `namespace.action` reference to app.connectors.namespace_action."""
    if uses not in _CACHE:
        module = "app.connectors." + uses.replace(".", "_")
        _CACHE[uses] = importlib.import_module(module)
    return _CACHE[uses]
