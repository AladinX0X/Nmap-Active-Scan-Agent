from loguru import logger

logger.add("nmap_scan.log", level="DEBUG", format="{time} {level} {massage}")

__all__ = [logger]