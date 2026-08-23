import logging
import sys

from src.core.config import settings


def setup_logging() -> logging.Logger:
    """Configures structured application logging."""
    log_format = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    logging.basicConfig(
        level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO),
        format=log_format,
        handlers=[logging.StreamHandler(sys.stdout)],
        force=True,
    )
    logger = logging.getLogger("threattrace")
    return logger


logger = setup_logging()
