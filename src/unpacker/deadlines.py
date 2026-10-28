"""Finite wall-clock plans; no instruction, memory or output limit changes."""
from dataclasses import dataclass
import math

EXPORT_GRACE_SECONDS = 5.0
CLEANUP_GRACE_SECONDS = 5.0
CONTROLLER_GRACE_SECONDS = 5.0
POST_DECODE_GRACE_SECONDS = 30.0


def positive_seconds(value, name='timeout'):
    if type(value) not in {int,float} or not math.isfinite(value) or value<=0:
        raise ValueError(name+' must be positive and finite')
    return float(value)


@dataclass(frozen=True)
class DeadlinePlan:
    decode_seconds: float
    job_seconds: float

    def __post_init__(self):
        object.__setattr__(self,'decode_seconds',positive_seconds(self.decode_seconds,'decode timeout'))
        object.__setattr__(self,'job_seconds',positive_seconds(self.job_seconds,'total timeout'))
        positive_seconds(self.launcher_seconds,'outer timeout')

    @classmethod
    def for_decode(cls, seconds):
        seconds=positive_seconds(seconds,'decode timeout')
        return cls(seconds,seconds+POST_DECODE_GRACE_SECONDS)

    @property
    def sandbox_seconds(self):return self.job_seconds+EXPORT_GRACE_SECONDS

    @property
    def launcher_seconds(self):return self.sandbox_seconds+CLEANUP_GRACE_SECONDS+CONTROLLER_GRACE_SECONDS

    def facts(self):
        return {'requested_decode_seconds':self.decode_seconds,'job_seconds':self.job_seconds,
          'sandbox_watchdog_seconds':self.sandbox_seconds,'recommended_outer_launcher_seconds':self.launcher_seconds,
          'decode_upper_bound_seconds':min(self.decode_seconds,self.job_seconds),
          'shorter_explicit_job_wins':self.job_seconds<self.decode_seconds}
