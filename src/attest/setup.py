from __future__ import annotations

from datetime import timedelta

from ring_sandbox import RingClient

from .clock import ExecutionClock
from .models import Schedule, Site, Worker, utcnow
from .store import Store, atomic


class SetupService:
    def __init__(self, store: Store, ring: RingClient, clock: ExecutionClock, grace_minutes: int):
        self.store, self.ring, self.clock = store, ring, clock
        self.grace = timedelta(minutes=grace_minutes)

    def discover(self) -> list[dict]:
        return [
            {
                "id": bundle.id,
                "name": bundle.name,
                "online": bundle.online,
                "camera": bool(bundle.capabilities and bundle.capabilities.is_camera),
                "contact_signal": bool(
                    bundle.status and bundle.status.attributes.contact_detection is not None
                ),
            }
            for bundle in self.ring.devices(include=["status", "capabilities"])
        ]

    def register_site(
        self, name: str, camera_id: str, sensor_id: str | None = None, *, supplied: Site | None = None
    ) -> Site:
        self.clock.now()
        account = self.ring.me().account_id
        devices = {bundle.id: bundle for bundle in self.ring.devices(include=["status", "capabilities"])}
        camera = devices.get(camera_id)
        if camera is None or not camera.capabilities or not camera.capabilities.is_camera:
            raise ValueError("select an accessible camera-capable Ring device")
        if camera.capabilities.is_multi_camera:
            raise ValueError("multi-camera devices require explicit component support before binding")
        if sensor_id:
            sensor = devices.get(sensor_id)
            if sensor is None or not sensor.status or sensor.status.attributes.contact_detection is None:
                raise ValueError("selected sensor must expose contact state; omit it if not available")
        if supplied and supplied.ring_account_id != account:
            raise ValueError("site account must match the authorized Ring account")
        site = supplied or Site(
            name=name, ring_account_id=account, door_camera_id=camera_id, door_sensor_id=sensor_id
        )
        site = site.model_copy(update={"created_at": utcnow()})
        with self.store.transaction():
            if (
                self.store.site(site.id)
                or self.store.site_for_device(camera_id)
                or (sensor_id and self.store.site_for_device(sensor_id))
            ):
                raise ValueError(
                    "site id or selected device is already bound; existing sites are not overwritten"
                )
            return self.store.put_site(site)

    @atomic
    def register_worker(self, worker: Worker) -> Worker:
        self.clock.now()
        if self.store.worker(worker.id):
            raise ValueError("worker id already exists; existing workers are not overwritten")
        return self.store.put_worker(worker.model_copy(update={"created_at": utcnow()}))

    @atomic
    def register_schedule(self, schedule: Schedule) -> Schedule:
        self.clock.now()
        if not self.store.site(schedule.site_id) or not self.store.worker(schedule.worker_id):
            raise ValueError("select an existing site and worker")
        if self.store.schedule(schedule.id):
            raise ValueError("schedule id already exists; existing schedules are not overwritten")
        if schedule.status != "scheduled" or schedule.cancelled_at is not None:
            raise ValueError("create a scheduled entry; cancel it through the cancellation action")
        for other in self.store.schedules_for_site(schedule.site_id):
            if other.status == "scheduled" and (
                schedule.window_start - self.grace <= other.window_end + self.grace
                and other.window_start - self.grace <= schedule.window_end + self.grace
            ):
                raise ValueError(
                    "arrival windows overlap after grace; ambiguous schedule matching is not supported"
                )
        return self.store.put_schedule(schedule.model_copy(update={"created_at": utcnow()}))

    @atomic
    def cancel_schedule(self, schedule_id: str) -> Schedule:
        schedule = self.store.schedule(schedule_id)
        if schedule is None:
            raise ValueError("schedule not found")
        if self.store.visit_for_schedule(schedule_id):
            raise ValueError("schedule already has observations; append a review instead of changing it")
        if schedule.status != "cancelled":
            schedule.status = "cancelled"
            schedule.cancelled_at = utcnow()
            self.store.put_schedule(schedule)
        return schedule
