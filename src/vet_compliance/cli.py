from __future__ import annotations

import argparse
import logging

from vet_compliance.cache import load_targets_cache, write_targets_cache
from vet_compliance.compliance.engine import ComplianceEngine
from vet_compliance.config import load_app_config, load_yaml
from vet_compliance.connectors.meraki import collect_meraki_targets
from vet_compliance.connectors.unifi import collapse_unifi_site_targets, collect_unifi_targets
from vet_compliance.exceptions import apply_exceptions
from vet_compliance.reporting.writers import write_reports


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Read-only UniFi and Meraki compliance auditor.")
    parser.add_argument("--config", default="config/config.yaml", help="Path to runtime config YAML.")
    parser.add_argument("--rules", default="config/compliance.yaml", help="Path to compliance rules YAML.")
    parser.add_argument("--env", default=".env", help="Path to .env containing secrets.")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    parser.add_argument("--cache-mode", choices=["off", "read", "refresh"], help="Override audit.cache.mode from config.")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    logging.basicConfig(level=getattr(logging, args.log_level), format="%(asctime)s %(levelname)s %(name)s %(message)s")
    logger = logging.getLogger(__name__)
    config = load_app_config(args.config, args.env)
    rules = load_yaml(args.rules)
    cache_config = config.get("audit", {}).get("cache", {})
    cache_mode = args.cache_mode or cache_config.get("mode", "off")
    cache_path = cache_config.get("path", "cache/target_cache.json")
    targets = load_targets_cache(cache_path) if cache_mode == "read" else None
    if targets is not None:
        logger.info("Loaded %s collected targets from cache %s.", len(targets), cache_path)
    else:
        targets = []
        logger.info("Collecting Meraki data first so cross-vendor UniFi checks have VLAN interface references.")
        if config.get("meraki", {}).get("max_networks"):
            logger.warning("Meraki max_networks is set; cross-vendor UniFi checks will only have partial Meraki reference data.")
        targets.extend(collect_meraki_targets(config))
        targets.extend(collect_unifi_targets(config))
        if cache_mode in {"read", "refresh"}:
            write_targets_cache(cache_path, targets)
            logger.info("Wrote %s collected targets to cache %s.", len(targets), cache_path)
    targets = apply_exceptions(targets, config)
    targets = collapse_unifi_site_targets(targets)
    report = ComplianceEngine(rules).audit(targets)
    paths = write_reports(report, config["audit"]["output_dir"])
    print(f"Audited {report.total_devices} targets. Compliance: {report.compliance_percent}%")
    print(f"Findings: {len(report.findings)}")
    for name, path in paths.items():
        print(f"{name}: {path}")


if __name__ == "__main__":
    main()
