"""Abstract base for RedGNAT intel subscribers."""
from __future__ import annotations

import abc
import logging
from typing import Iterator

from redgnat.config import RedGNATConfig
from redgnat.orm.models import IntelFeed

logger = logging.getLogger(__name__)


class IntelSubscriber(abc.ABC):
    """
    Abstract base class for intel feed subscribers.

    Subclasses poll an external system (GNAT, SandGNAT) and yield
    IntelFeed objects that the normalizer converts into EmulationScenarios.

    Parameters
    ----------
    config : RedGNATConfig
        Loaded configuration.
    """

    def __init__(self, config: RedGNATConfig) -> None:
        self.config = config

    @abc.abstractmethod
    def poll(self) -> Iterator[IntelFeed]:
        """
        Poll the external system and yield actionable IntelFeed records.

        Yields
        ------
        IntelFeed
            One record per actionable intel item (campaign, analysis, etc.).
        """
        ...

    @abc.abstractmethod
    def health_check(self) -> bool:
        """Return True if the external system is reachable."""
        ...
