from bubblepwn.context import Context, Finding


def test_singleton_returns_same_instance():
    a = Context.get()
    b = Context.get()
    assert a is b


def test_reset_drops_singleton():
    a = Context.get()
    Context._reset()
    b = Context.get()
    assert a is not b


def test_set_target_normalizes_scheme():
    ctx = Context.get()
    target = ctx.set_target("app.example.com")
    assert target.scheme == "https"
    assert target.host == "app.example.com"


def test_set_target_purges_findings_on_host_change():
    ctx = Context.get()
    ctx.set_target("https://a.example.com")
    ctx.add_finding(Finding(module="m", title="from A"))
    ctx.add_finding(Finding(module="m", title="also A"))
    assert len(ctx.findings) == 2

    ctx.set_target("https://b.example.com")
    assert ctx.findings == []


def test_set_target_keeps_findings_on_same_host():
    ctx = Context.get()
    ctx.set_target("https://a.example.com")
    ctx.add_finding(Finding(module="m", title="from A"))
    # Same host — findings must survive.
    ctx.set_target("https://a.example.com/some/page")
    assert len(ctx.findings) == 1


def test_set_target_resets_schema_on_host_change():
    from bubblepwn.bubble.schema import BubblePage
    ctx = Context.get()
    ctx.set_target("https://a.example.com")
    ctx.schema.pages["index"] = BubblePage(name="index")
    assert "index" in ctx.schema.pages

    ctx.set_target("https://b.example.com")
    assert ctx.schema.pages == {}


def test_invalid_url_raises():
    import pytest
    with pytest.raises(ValueError):
        Context.get().set_target("://not-a-url")
