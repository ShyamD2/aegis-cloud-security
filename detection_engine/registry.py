"""Rule registry managing active detection rules."""

from detection_engine.rules import ALL_RULES, DetectionRule


class RuleRegistry:
    """Registry maintaining initialized detection rules."""

    def __init__(self, load_defaults: bool = True) -> None:
        self._rules: dict[str, DetectionRule] = {}
        if load_defaults:
            for rule_cls in ALL_RULES:
                self.register(rule_cls())

    def register(self, rule: DetectionRule) -> None:
        """Register a new detection rule instance."""
        self._rules[rule.rule_id] = rule

    def unregister(self, rule_id: str) -> None:
        """Remove a rule from the active registry."""
        self._rules.pop(rule_id, None)

    def get_rule(self, rule_id: str) -> DetectionRule | None:
        """Retrieve a specific rule by ID."""
        return self._rules.get(rule_id)

    def list_rules(self) -> list[DetectionRule]:
        """List all active detection rules."""
        return list(self._rules.values())

    def count(self) -> int:
        """Return the number of registered rules."""
        return len(self._rules)
