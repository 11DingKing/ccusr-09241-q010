"""领域模型：例外生命周期、拓扑校验。"""

from datetime import timedelta

from policy_wave_control.domain.models import (
    Device,
    DomainError,
    PolicyException,
    Zone,
)
from tests.support import T0, ServiceTestCase


class ExceptionLifecycleTests(ServiceTestCase):
    def _exc(self, **kwargs) -> PolicyException:
        defaults = dict(
            id="exc-1", rule_id="rb", reason="r", created_by="ops",
            valid_from=T0, valid_until=T0 + timedelta(days=1),
        )
        defaults.update(kwargs)
        return PolicyException(**defaults)

    def test_active_expired_revoked_states(self) -> None:
        exc = self._exc()
        self.assertTrue(exc.is_active(T0))
        self.assertEqual(exc.state_at(T0), "active")
        self.assertEqual(exc.state_at(T0 + timedelta(days=2)), "expired")
        self.assertFalse(exc.is_active(T0 + timedelta(days=2)))
        exc.revoke(T0 + timedelta(hours=1))
        self.assertEqual(exc.state_at(T0 + timedelta(hours=2)), "revoked")

    def test_renew_only_extends(self) -> None:
        exc = self._exc(valid_until=T0 + timedelta(days=1))
        exc.renew(T0 + timedelta(days=30), "ops", T0)
        self.assertEqual(exc.valid_until, T0 + timedelta(days=30))
        self.assertEqual(len(exc.renewals), 1)
        with self.assertRaises(DomainError):
            exc.renew(T0 + timedelta(hours=1), "ops", T0)
        exc.revoke(T0 + timedelta(days=2))
        with self.assertRaises(DomainError):
            exc.revoke(T0 + timedelta(days=3))

    def test_valid_window_must_be_positive(self) -> None:
        with self.assertRaises(DomainError):
            self._exc(valid_from=T0, valid_until=T0)


class TopologyValidationTests(ServiceTestCase):
    def test_unknown_zone_kind_rejected(self) -> None:
        with self.assertRaises(DomainError):
            Zone(id="z", name="x", kind="guest")

    def test_device_and_edge_zone_refs_validated(self) -> None:
        with self.assertRaises(DomainError):
            self.service.add_snapshot(
                name="bad",
                zones=[{"id": "zp", "name": "p", "kind": "personal"}],
                devices=[{"id": "d1", "zone_id": "zz", "name": "d"}],
                edges=[],
            )
        with self.assertRaises(DomainError):
            self.service.add_snapshot(
                name="bad",
                zones=[{"id": "zp", "name": "p", "kind": "personal"}],
                devices=[],
                edges=[{"src_zone": "zp", "dst_zone": "zz", "service": "x"}],
            )

    def test_device_capability_check(self) -> None:
        d = Device(id="d", zone_id="zp", name="d", capabilities=["a", "b"])
        self.assertTrue(d.supports(["a"]))
        self.assertTrue(d.supports(["a", "b"]))
        self.assertFalse(d.supports(["a", "c"]))
